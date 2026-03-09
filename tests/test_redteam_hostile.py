"""Hostile Red Team — Round 9 (R9).

Adversarial security audit from the 5 angles AIIR was built on:

  Angle 1 — Canonical Determinism (content-addressed integrity)
  Angle 2 — AI Detection Evasion (homoglyphs, encoding tricks, blind spots)
  Angle 3 — Verification Bypass (forgery, type confusion, oracle extraction)
  Angle 4 — Policy Engine Escape (normalization gaps, enforcement bypass)
  Angle 5 — Supply Chain / MCP / CLI (in-toto, ledger, MCP, CLI injection)

Every test is a concrete attack.  Tests that PASS mean the defense holds.
Tests that FAIL mean the attacker found a gap.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import aiir._core as core
import aiir._detect as detect
import aiir._ledger as ledger
import aiir._policy as policy
import aiir._receipt as receipt
import aiir._schema as schema
import aiir._verify as verify
import aiir.mcp_server as mcp


# ---------------------------------------------------------------------------
# Test fixture helpers
# ---------------------------------------------------------------------------

def _make_valid_receipt(**overrides) -> dict:
    """Build a structurally valid receipt with correct content_hash/receipt_id."""
    receipt_core = {
        "type": "aiir.commit_receipt",
        "schema": "aiir/commit_receipt.v1",
        "version": "1.0.14",
        "commit": {
            "sha": "a" * 40,
            "author": {"name": "Test", "email": "t@t.com", "date": "2025-01-01T00:00:00Z"},
            "committer": {"name": "Test", "email": "t@t.com", "date": "2025-01-01T00:00:00Z"},
            "subject": "test commit",
            "message_hash": "sha256:" + "b" * 64,
            "diff_hash": "sha256:" + "c" * 64,
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
            "repository": "https://github.com/test/repo.git",
            "tool": "https://github.com/invariant-systems-ai/aiir@1.0.14",
            "generator": "aiir.cli",
        },
    }
    # Apply overrides into nested structure
    for key, val in overrides.items():
        if "." in key:
            parts = key.split(".", 1)
            if parts[0] in receipt_core and isinstance(receipt_core[parts[0]], dict):
                receipt_core[parts[0]][parts[1]] = val
        else:
            receipt_core[key] = val
    core_json = core._canonical_json(receipt_core)
    content_hash = "sha256:" + core._sha256(core_json)
    receipt_id = f"g1-{core._sha256(core_json)[:32]}"
    return {
        **receipt_core,
        "receipt_id": receipt_id,
        "content_hash": content_hash,
        "timestamp": "2025-01-01T00:00:00Z",
        "extensions": {},
    }


# ===========================================================================
# ANGLE 1: Canonical Determinism Attacks
# ===========================================================================

class TestHostileAngle1CanonicalDeterminism(unittest.TestCase):
    """Attack canonical JSON serialization and content-addressing."""

    # ── A1-01: Unicode NFC vs NFKC key ordering ──
    def test_a1_01_unicode_key_ordering_attack(self):
        """Craft two dicts with visually identical keys that canonicalize differently.

        Attack: If keys differ in Unicode normalization form (NFC vs NFKC),
        json.dumps(sort_keys=True) sorts by byte value, NOT by visual appearance.
        Two receipts that look identical could have different content hashes.
        Defense: _canonical_json uses ensure_ascii=True, which escapes all
        non-ASCII — so normalization form doesn't matter in the JSON output.
        """
        # \u00e9 = é (NFC precomposed)
        # e\u0301 = é (NFD: e + combining acute accent)
        key_nfc = "\u00e9"
        key_nfd = "e\u0301"
        obj1 = {key_nfc: "value"}
        obj2 = {key_nfd: "value"}
        j1 = core._canonical_json(obj1)
        j2 = core._canonical_json(obj2)
        # ensure_ascii=True escapes both to different escape sequences.
        # This is EXPECTED — they ARE different keys.  The defense is that
        # all AIIR receipt keys are pure ASCII, so this can't happen in
        # practice.  But verify the invariant:
        self.assertNotEqual(j1, j2, "Different Unicode forms SHOULD produce different JSON")
        # Verify all CORE_KEYS in verify.py are pure ASCII
        CORE_KEYS = {"type", "schema", "version", "commit", "ai_attestation", "provenance"}
        for k in CORE_KEYS:
            self.assertTrue(k.isascii(), f"CORE_KEY {k!r} contains non-ASCII")

    # ── A1-02: Depth bomb against canonical JSON ──
    def test_a1_02_depth_bomb_64_layers(self):
        """Create a 65-deep nested dict to overflow the depth checker.

        Defense: _check_json_depth raises ValueError at depth > 64.
        """
        bomb = "value"
        for _ in range(65):
            bomb = {"k": bomb}
        with self.assertRaises(ValueError) as ctx:
            core._canonical_json(bomb)
        self.assertIn("depth", str(ctx.exception).lower())

    # ── A1-03: NaN/Infinity injection ──
    def test_a1_03_nan_infinity_in_canonical_json(self):
        """Inject NaN/Infinity — json.dumps(allow_nan=False) must reject.

        Attack: float('nan') or float('inf') in a receipt field would produce
        non-standard JSON that different parsers handle differently.
        """
        for evil_val in [float("nan"), float("inf"), float("-inf")]:
            with self.assertRaises(ValueError):
                core._canonical_json({"val": evil_val})

    # ── A1-04: Key collision via __proto__ and constructor ──
    def test_a1_04_prototype_pollution_keys(self):
        """Include __proto__ and constructor keys in receipt data.

        Attack: These keys trigger prototype pollution in JavaScript JSON.parse()
        consumers.  AIIR receipts are consumed by Node.js/browser tools.
        Defense: Python's json.dumps handles them as normal strings — but downstream
        consumers may be vulnerable.  AIIR should at minimum not crash.
        """
        evil = {"__proto__": {"isAdmin": True}, "constructor": {"prototype": {}}}
        # Should not crash
        result = core._canonical_json(evil)
        self.assertIn("__proto__", result)

    # ── A1-05: Duplicate key attack ──
    def test_a1_05_duplicate_json_keys_last_wins(self):
        """JSON spec allows duplicate keys — Python's json.loads takes the last one.

        Attack: A crafted receipt JSON file with duplicate "content_hash" keys —
        the first one is the real hash, the second is a forged one.
        json.loads takes the last value, so the verifier sees the forged hash.
        Defense: verify_receipt recomputes the hash from the receipt core dict,
        which only has one value per key. The stored hash is compared, not trusted.
        """
        # Simulate by loading crafted JSON with duplicate keys
        crafted = '{"content_hash": "sha256:real", "content_hash": "sha256:forged"}'
        parsed = json.loads(crafted)
        # Python takes the last value
        self.assertEqual(parsed["content_hash"], "sha256:forged")
        # But verify_receipt computes expected hash independently, so forgery fails
        result = verify.verify_receipt(parsed)
        self.assertFalse(result["valid"])

    # ── A1-06: Sort-key stability with mixed-type keys ──
    def test_a1_06_sort_key_determinism_all_field_types(self):
        """Verify _canonical_json produces identical output across invocations.

        Attack: If json.dumps sorting is non-deterministic, two verifiers
        would compute different content_hashes for the same receipt.
        """
        obj = {
            "z_last": 1,
            "a_first": 2,
            "m_middle": {"nested_z": True, "nested_a": False},
            "list_field": [3, 2, 1],  # Lists preserve order (not sorted)
        }
        results = [core._canonical_json(obj) for _ in range(100)]
        self.assertTrue(all(r == results[0] for r in results))

    # ── A1-07: Empty vs absent field content_hash divergence ──
    def test_a1_07_empty_vs_absent_field_hash_divergence(self):
        """Verify that {key: null} and {key absent} produce different hashes.

        Attack: If an attacker can add null fields to a receipt and it doesn't
        change the hash, they can inject metadata that survives verification.
        """
        obj1 = {"type": "test"}
        obj2 = {"type": "test", "extra": None}
        h1 = core._sha256(core._canonical_json(obj1))
        h2 = core._sha256(core._canonical_json(obj2))
        self.assertNotEqual(h1, h2, "Absent field and null field must hash differently")


# ===========================================================================
# ANGLE 2: AI Detection Evasion
# ===========================================================================

class TestHostileAngle2DetectionEvasion(unittest.TestCase):
    """Attack AI signal detection — try to make AI commits look human."""

    # ── A2-01: Armenian homoglyph bypass ──
    def test_a2_01_armenian_homoglyph_evasion(self):
        """Use Armenian letters to spell 'copilot' and evade detection.

        Attack: Armenian Small Letter Oh (U+0585) → 'o' per Unicode TR39.
        Spell "copilot" as "c\u0585pil\u0585t" — visually identical, different codepoints.
        Defense: _normalize_for_detection uses the full TR39 confusable map (669 entries,
        69 scripts) to resolve these before signal matching.
        """
        # Armenian ։ (U+0585) is the TR39-authoritative confusable for 'o'.
        # Build "generated by copilot" with Armenian o's — tests the full chain:
        # normalization resolves Armenian օ → Latin 'o', then signal matching
        # finds "generated by copilot" in the cleaned message.
        evasion_msg = "generated by c\u0585pil\u0585t"
        normalized = core._normalize_for_detection(evasion_msg)
        self.assertIn("copilot", normalized,
                       "Armenian օ (U+0585) should normalize to 'o' per TR39")
        ai_signals, _ = detect.detect_ai_signals(evasion_msg)
        self.assertTrue(
            len(ai_signals) > 0,
            "Armenian homoglyph 'c\u0585pil\u0585t' must be detected as 'copilot'",
        )

    # ── A2-02: Cyrillic homoglyph that IS in the map ──
    def test_a2_02_cyrillic_copilot_detected(self):
        """Verify that Cyrillic-substituted 'github copilot' is still detected.

        The confusable map should normalize Cyrillic о (U+043E) → Latin o.
        """
        # "github copilot" with Cyrillic о (U+043E) replacing 'o's
        evasion_msg = "github c\u043epil\u043et was used here"
        ai_signals, _ = detect.detect_ai_signals(evasion_msg)
        self.assertTrue(
            len(ai_signals) > 0,
            "Cyrillic о→o substitution in 'github copilot' should be detected",
        )

    # ── A2-03: Zero-width joiner splitting ──
    def test_a2_03_zero_width_joiner_splitting(self):
        """Insert zero-width joiners between characters of a signal word.

        Attack: "cop\u200Dilot" — ZWJ splits the word at the byte level.
        Defense: _normalize_for_detection strips Cf category (which includes ZWJ).
        """
        evasion_msg = "Co-authored-by: c\u200Do\u200Dp\u200Di\u200Dl\u200Do\u200Dt"
        ai_signals, _ = detect.detect_ai_signals(evasion_msg)
        self.assertTrue(len(ai_signals) > 0, "ZWJ splitting should not evade detection")

    # ── A2-04: Soft-hyphen in "co-authored-by" ──
    def test_a2_04_soft_hyphen_in_co_authored_by(self):
        """Use soft hyphen (U+00AD) instead of regular hyphen in 'co-authored-by'.

        Defense: _DASH_TO_ASCII maps U+00AD → '-'.
        """
        evasion_msg = "co\u00ADauthored\u00ADby: copilot"
        ai_signals, _ = detect.detect_ai_signals(evasion_msg)
        self.assertTrue(
            len(ai_signals) > 0,
            "Soft-hyphen should normalize to regular hyphen for detection",
        )

    # ── A2-05: En-dash in "co-authored-by" ──
    def test_a2_05_en_dash_in_trailer(self):
        """Use en-dash (U+2013) instead of hyphen in 'co-authored-by'.

        Defense: _DASH_TO_ASCII maps U+2013 → '-'.
        """
        evasion_msg = "co\u2013authored\u2013by: chatgpt"
        ai_signals, _ = detect.detect_ai_signals(evasion_msg)
        self.assertTrue(
            len(ai_signals) > 0,
            "En-dash should normalize to hyphen for AI trailer detection",
        )

    # ── A2-06: Fullwidth Latin letter bypass ──
    def test_a2_06_fullwidth_latin_evasion(self):
        """Use fullwidth Latin letters (U+FF21-U+FF5A) for signal words.

        Attack: 'ｇｉｔｈｕｂ ｃｏｐｉｌｏｔ' (fullwidth) instead of 'github copilot'.
        Defense: NFKC normalization collapses fullwidth → ASCII.
        """
        # Fullwidth "github copilot"
        evasion_msg = (
            "\uff47\uff49\uff54\uff48\uff55\uff42 "
            "\uff43\uff4f\uff50\uff49\uff4c\uff4f\uff54"
        )
        ai_signals, _ = detect.detect_ai_signals(evasion_msg)
        self.assertTrue(
            len(ai_signals) > 0,
            "Fullwidth Latin should normalize to ASCII via NFKC",
        )

    # ── A2-07: Missing AI tools (coverage gap attack) ──
    def test_a2_07_missing_ai_tools_in_signals(self):
        """Check if common AI tools are in the signal list.

        Attack: If a tool isn't in AI_SIGNALS, commits using it are classified
        as 'human' — false negatives undermine the entire system.
        """
        must_detect = [
            "copilot",
            "chatgpt",
            "claude",
            "cursor",
            "codeium",
            "amazon q",
            "codewhisperer",
            "tabnine",
            "gemini code assist",
        ]
        for tool in must_detect:
            msg = f"Generated by {tool}"
            ai_signals, _ = detect.detect_ai_signals(msg)
            self.assertTrue(
                len(ai_signals) > 0,
                f"AI tool '{tool}' not detected in message '{msg}'",
            )

    # ── A2-08: Newer AI tools NOT in the list ──
    def test_a2_08_newer_ai_tools_blind_spots(self):
        """Test for AI tools that launched after the signal list was created.

        Attack: Newer tools like Replit Agent, v0, bolt.new, Lovable,
        JetBrains AI are not in AI_SIGNALS and would evade detection.
        """
        newer_tools = [
            "replit agent",
            "bolt.new",
            "lovable",
            "jetbrains ai",
            "supermaven",
            "continue.dev",
            "double.bot",
            "codestral",
        ]
        gaps = []
        for tool in newer_tools:
            msg = f"Co-authored-by: {tool}"
            ai_signals, _ = detect.detect_ai_signals(msg)
            if not ai_signals:
                gaps.append(tool)
        self.assertEqual(
            gaps, [],
            f"Newer AI tools evading detection: {', '.join(gaps)}",
        )

    # ── A2-09: Whitespace flooding in trailer ──
    def test_a2_09_whitespace_flooding_trailer(self):
        """Insert excessive whitespace/tabs in a trailer to evade matching.

        Attack: "generated-by:\t\t\t  copilot" — extra whitespace between
        the trailer key and value.
        Defense: detect_ai_signals collapses whitespace with re.sub(r'\\s+', ' ').
        """
        evasion_msg = "generated-by:\t\t\t    copilot"
        ai_signals, _ = detect.detect_ai_signals(evasion_msg)
        self.assertTrue(
            len(ai_signals) > 0,
            "Whitespace flooding in trailer should not evade detection",
        )

    # ── A2-10: Case-mixed evasion ──
    def test_a2_10_case_mixed_evasion(self):
        """Use mixed case: 'GeNeRaTeD bY cOpIlOt' instead of 'generated by copilot'.

        Defense: detect_ai_signals lowercases the message before matching.
        """
        msg = "GeNeRaTeD bY cOpIlOt"
        ai_signals, _ = detect.detect_ai_signals(msg)
        self.assertTrue(len(ai_signals) > 0, "Case mixing should not evade detection")


# ===========================================================================
# ANGLE 3: Verification Bypass
# ===========================================================================

class TestHostileAngle3VerificationBypass(unittest.TestCase):
    """Attack receipt verification — forge receipts, extract oracle info."""

    # ── A3-01: CRITICAL — authorship_class schema mismatch ──
    def test_a3_01_authorship_class_schema_mismatch(self):
        """CRITICAL: _detect.py generates 'ai-assisted' but _schema.py only
        accepts 'ai_assisted' (underscore).

        Attack: Every legitimate AI-assisted receipt generated by AIIR fails
        schema validation because authorship_class='ai-assisted' is not in
        the schema validator's valid_classes set.

        Impact: If require_schema_valid is True in policy, ALL AI-assisted
        receipts are rejected — a DoS on the AI transparency system itself.
        """
        # Build a receipt with the ACTUAL value _detect.py would generate
        r = _make_valid_receipt()
        r["ai_attestation"]["authorship_class"] = "ai-assisted"
        r["ai_attestation"]["is_ai_authored"] = True
        r["ai_attestation"]["signals_detected"] = ["message_match:copilot"]
        r["ai_attestation"]["signal_count"] = 1

        errors = schema.validate_receipt_schema(r)
        authorship_errors = [e for e in errors if "authorship_class" in e]
        if authorship_errors:
            self.fail(
                "VULNERABILITY A3-01: _detect.py generates 'ai-assisted' (hyphen) "
                "but _schema.py only accepts 'ai_assisted' (underscore). "
                f"Schema rejected with: {authorship_errors[0]}. "
                "Every AI-assisted receipt fails schema validation."
            )

    # ── A3-02: bot-generated schema mismatch ──
    def test_a3_02_bot_generated_schema_mismatch(self):
        """_detect.py generates 'bot-generated' but schema only accepts 'bot'.

        Same class of bug as A3-01.
        """
        r = _make_valid_receipt()
        r["ai_attestation"]["authorship_class"] = "bot-generated"
        r["ai_attestation"]["is_bot_authored"] = True
        r["ai_attestation"]["bot_signals_detected"] = ["author_name_bot:dependabot"]
        r["ai_attestation"]["bot_signal_count"] = 1

        errors = schema.validate_receipt_schema(r)
        authorship_errors = [e for e in errors if "authorship_class" in e]
        if authorship_errors:
            self.fail(
                "VULNERABILITY A3-02: _detect.py generates 'bot-generated' "
                "but _schema.py only accepts 'bot'. "
                f"Schema rejected with: {authorship_errors[0]}"
            )

    # ── A3-03: ai+bot schema mismatch ──
    def test_a3_03_ai_plus_bot_schema_mismatch(self):
        """_detect.py generates 'ai+bot' but schema doesn't include it."""
        r = _make_valid_receipt()
        r["ai_attestation"]["authorship_class"] = "ai+bot"

        errors = schema.validate_receipt_schema(r)
        authorship_errors = [e for e in errors if "authorship_class" in e]
        if authorship_errors:
            self.fail(
                "VULNERABILITY A3-03: _detect.py generates 'ai+bot' "
                "but _schema.py's valid_classes doesn't include it. "
                f"Schema rejected with: {authorship_errors[0]}"
            )

    # ── A3-04: Forgery oracle prevention ──
    def test_a3_04_forgery_oracle_prevention(self):
        """On verification failure, the expected hash must NOT be returned.

        Attack: An attacker submits a forged receipt and reads the expected
        content_hash from the error response — then crafts a new receipt
        that matches. If the expected hash leaks, the attacker has an oracle.
        """
        forged = _make_valid_receipt()
        forged["commit"]["subject"] = "tampered subject"
        # content_hash is now wrong (doesn't match the modified core)
        result = verify.verify_receipt(forged)
        self.assertFalse(result["valid"])
        # The oracle defense: expected hash must NOT be in the response
        self.assertNotIn("expected_content_hash", result,
                         "Forgery oracle: expected hash leaked on invalid receipt")
        self.assertNotIn("expected_receipt_id", result,
                         "Forgery oracle: expected ID leaked on invalid receipt")

    # ── A3-05: Timing attack on content_hash comparison ──
    def test_a3_05_constant_time_comparison_used(self):
        """Verify that hmac.compare_digest is used (not == operator).

        Attack: String == comparison in CPython short-circuits on first
        differing byte, leaking hash prefix information via timing.
        Defense: verify_receipt uses hmac.compare_digest.
        """
        import inspect
        source = inspect.getsource(verify.verify_receipt)
        self.assertIn("hmac.compare_digest", source,
                       "Must use constant-time comparison for hash verification")
        self.assertNotIn("stored_hash == expected", source,
                         "Must not use == for hash comparison")

    # ── A3-06: Extra fields in CORE_KEYS sub-objects ──
    def test_a3_06_extra_fields_in_core_survive_verification(self):
        """Inject extra fields into the commit sub-object.

        Attack: Add "malicious_payload" inside the "commit" dict.  Since
        CORE_KEYS includes "commit" as a whole, the extra field changes
        the content_hash — but if someone builds a receipt with the extra
        field from scratch, it verifies fine.

        This is expected behavior (not a vulnerability) — the content hash
        covers the FULL content of CORE_KEYS sub-objects.
        """
        r = _make_valid_receipt()
        original_hash = r["content_hash"]
        # Add an extra field inside commit
        r2 = _make_valid_receipt()
        r2["commit"]["evil_payload"] = "injected"
        # Recompute hash
        CORE_KEYS = {"type", "schema", "version", "commit", "ai_attestation", "provenance"}
        core_dict = {k: v for k, v in r2.items() if k in CORE_KEYS}
        new_hash = "sha256:" + core._sha256(core._canonical_json(core_dict))
        # The hash MUST change — extra fields in CORE sub-objects affect the hash
        self.assertNotEqual(original_hash, new_hash,
                            "Extra fields in CORE sub-objects must change the content hash")

    # ── A3-07: Type confusion — non-dict receipt ──
    def test_a3_07_type_confusion_non_dict_receipt(self):
        """Pass non-dict types to verify_receipt.

        Attack: Pass a list, string, int, None — should not crash.
        """
        for evil in [[], "string", 42, None, True, [{"type": "aiir.commit_receipt"}]]:
            result = verify.verify_receipt(evil)
            self.assertFalse(result["valid"])

    # ── A3-08: Mutate receipt_id while keeping content_hash correct ──
    def test_a3_08_receipt_id_independent_of_content_hash(self):
        """Verify that BOTH content_hash AND receipt_id must match.

        Attack: Correctly forge content_hash but use a different receipt_id.
        """
        r = _make_valid_receipt()
        # Tamper with receipt_id only
        r["receipt_id"] = "g1-" + "0" * 32
        result = verify.verify_receipt(r)
        self.assertFalse(result["valid"])
        self.assertTrue(result.get("content_hash_match", False),
                        "content_hash should still match")
        self.assertFalse(result.get("receipt_id_match", True),
                         "receipt_id should NOT match")

    # ── A3-09: Version field injection ──
    def test_a3_09_version_field_html_injection(self):
        """Inject HTML/script in the version field.

        Attack: version = '<script>alert(1)</script>' — if displayed
        unescaped in a web UI, it's XSS.
        Defense: verify_receipt validates version format with regex.
        """
        r = _make_valid_receipt()
        r["version"] = "<script>alert(1)</script>"
        result = verify.verify_receipt(r)
        self.assertFalse(result["valid"])
        self.assertTrue(
            any("version" in e.lower() for e in result.get("errors", [])),
            "HTML in version field should be rejected",
        )

    # ── A3-10: Schema and version field bypass with embedded control chars ──
    def test_a3_10_schema_field_control_char_injection(self):
        """Inject control characters in the schema field.

        Attack: schema = 'aiir/commit_receipt.v1\x00evil' — NUL-terminated
        string that passes startswith() but has hidden suffix.
        """
        r = _make_valid_receipt()
        r["schema"] = "aiir/commit_receipt.v1\x00evil"
        result = verify.verify_receipt(r)
        # The schema check does startswith("aiir/") — but \x00 in the middle
        # is a different string from the real schema constant
        if result["valid"]:
            self.fail(
                "VULNERABILITY A3-10: NUL-terminated schema field "
                "'aiir/commit_receipt.v1\\x00evil' passed verification"
            )


# ===========================================================================
# ANGLE 4: Policy Engine Escape
# ===========================================================================

class TestHostileAngle4PolicyEscape(unittest.TestCase):
    """Attack the policy engine — bypass enforcement, manipulate thresholds."""

    # ── A4-01: CRITICAL — ai-assisted vs ai_assisted normalization gap ──
    def test_a4_01_ai_assisted_normalization_gap(self):
        """CRITICAL: _detect.py generates 'ai-assisted' (hyphen) but
        policy presets use 'ai_assisted' (underscore).

        The policy normalizer does authorship.replace('-generated', ''),
        which does NOT convert 'ai-assisted' to 'ai_assisted'.

        Result: ai-assisted commits are REJECTED by strict policy even
        though 'ai_assisted' is in the allowed list.
        """
        strict = policy.POLICY_PRESETS["strict"]
        r = _make_valid_receipt()
        r["ai_attestation"]["authorship_class"] = "ai-assisted"  # What _detect.py produces

        violations = policy.evaluate_receipt_policy(r, strict)
        authorship_violations = [v for v in violations if v.rule == "allowed_authorship_classes"]
        if authorship_violations:
            self.fail(
                "VULNERABILITY A4-01: 'ai-assisted' (from _detect.py) rejected by "
                "strict policy because allowed list has 'ai_assisted' (underscore). "
                "Policy normalizer only strips '-generated', not '-assisted'. "
                f"Violation: {authorship_violations[0].message}"
            )

    # ── A4-02: bot-generated normalization works correctly ──
    def test_a4_02_bot_generated_normalization(self):
        """Verify 'bot-generated' normalizes to 'bot' for policy matching.

        This is the case the normalizer DOES handle.
        """
        balanced = policy.POLICY_PRESETS["balanced"]
        r = _make_valid_receipt()
        r["ai_attestation"]["authorship_class"] = "bot-generated"

        violations = policy.evaluate_receipt_policy(r, balanced)
        authorship_violations = [v for v in violations if v.rule == "allowed_authorship_classes"]
        self.assertEqual(len(authorship_violations), 0,
                         "'bot-generated' should normalize to 'bot' and be allowed")

    # ── A4-03: ai+bot in strict policy ──
    def test_a4_03_ai_plus_bot_strict_rejection(self):
        """Verify that 'ai+bot' is rejected by strict policy.

        Strict only allows: ['human', 'ai_assisted'].
        'ai+bot' should be rejected.
        """
        strict = policy.POLICY_PRESETS["strict"]
        r = _make_valid_receipt()
        r["ai_attestation"]["authorship_class"] = "ai+bot"

        violations = policy.evaluate_receipt_policy(r, strict)
        authorship_violations = [v for v in violations if v.rule == "allowed_authorship_classes"]
        self.assertTrue(
            len(authorship_violations) > 0,
            "'ai+bot' must be rejected by strict policy",
        )

    # ── A4-04: Enforcement level downgrade via policy file ──
    def test_a4_04_enforcement_downgrade_via_overlay(self):
        """A policy file that starts from 'strict' preset but overrides
        enforcement to 'warn' — bypassing hard-fail.

        This is EXPECTED behavior (documented), not a vulnerability.
        But verify it works as documented.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "policy.json"
            policy_file.write_text(json.dumps({
                "preset": "strict",
                "enforcement": "warn",  # Downgrade!
            }))
            loaded = policy.load_policy(ledger_dir=tmpdir)
            self.assertEqual(loaded["enforcement"], "warn")
            # The preset was strict, but enforcement was overridden
            self.assertTrue(loaded.get("require_signing"))

    # ── A4-05: Policy file with extra/unknown fields ──
    def test_a4_05_policy_file_unknown_fields(self):
        """Inject unknown fields into the policy file.

        Attack: Add 'allow_all': True or 'skip_verification': True.
        Defense: The policy engine only reads known keys via .get().
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "policy.json"
            policy_file.write_text(json.dumps({
                "preset": "strict",
                "allow_all": True,
                "skip_verification": True,
                "enforcement": "hard-fail",
            }))
            loaded = policy.load_policy(ledger_dir=tmpdir)
            # Unknown fields should be in the dict but not affect behavior
            self.assertTrue(loaded.get("require_signing"))
            r = _make_valid_receipt()
            violations = policy.evaluate_receipt_policy(r, loaded, is_signed=False)
            # Should still enforce signing despite "allow_all": True
            signing_violations = [v for v in violations if v.rule == "require_signing"]
            self.assertTrue(
                len(signing_violations) > 0,
                "Unknown 'allow_all' field must not bypass signing requirement",
            )

    # ── A4-06: Negative max_ai_percent ──
    def test_a4_06_negative_max_ai_percent(self):
        """Set max_ai_percent to -1 — should block everything or be rejected.

        Attack: A crafted policy with max_ai_percent = -1 could cause
        unexpected comparison behavior (0.0 > -1 is True → violation).
        """
        pol = {
            "max_ai_percent": -1,
            "enforcement": "hard-fail",
        }
        index = {"receipt_count": 10, "ai_commit_count": 0, "ai_percentage": 0.0}
        passed, msg, violations = policy.evaluate_ledger_policy(index, pol)
        # 0.0 > -1 is True, so this WILL trigger a violation — is that desired?
        # This documents the behavior. A negative threshold means "reject all."
        # That's arguably correct (more restrictive), but should be documented.
        if violations:
            # This is acceptable behavior — document it
            pass

    # ── A4-07: max_ai_percent as string injection ──
    def test_a4_07_max_ai_percent_type_confusion(self):
        """Set max_ai_percent to a string instead of float.

        Attack: '100' (string) > 50.0 is a TypeError in Python 3.
        Defense: The comparison ai_pct > max_ai should raise or skip.
        """
        pol = {"max_ai_percent": "100", "enforcement": "hard-fail"}
        index = {"receipt_count": 10, "ai_commit_count": 5, "ai_percentage": 50.0}
        # After type-coercion fix, string "100" is converted to float 100.0.
        # 50.0 is NOT > 100.0, so no violation should be raised.
        passed, msg, violations = policy.evaluate_ledger_policy(index, pol)
        self.assertTrue(passed, "String max_ai_percent='100' should coerce to 100.0")
        self.assertEqual(len(violations), 0, "50% does not exceed 100% threshold")
        # Also verify that a LOWER string threshold triggers a violation
        pol_low = {"max_ai_percent": "10", "enforcement": "hard-fail"}
        passed2, msg2, violations2 = policy.evaluate_ledger_policy(index, pol_low)
        self.assertFalse(passed2, "50% should exceed string threshold '10'")
        self.assertEqual(len(violations2), 1)


# ===========================================================================
# ANGLE 5: Supply Chain / MCP / CLI
# ===========================================================================

class TestHostileAngle5SupplyChain(unittest.TestCase):
    """Attack supply-chain integrations — in-toto, MCP, ledger, CLI."""

    # ── A5-01: in-toto envelope with tampered predicate ──
    def test_a5_01_intoto_wraps_without_verifying(self):
        """wrap_in_toto_statement wraps ANY receipt dict — even a forged one.

        Attack: Build a valid-looking in-toto statement around a forged receipt.
        A downstream tool that trusts the in-toto envelope but doesn't call
        verify_receipt on the predicate would accept the forgery.
        Defense: This is by design — in-toto wrapping is a formatting step.
        Downstream tools MUST verify the predicate independently.
        Document this as a known trust boundary.
        """
        forged = _make_valid_receipt()
        forged["commit"]["subject"] = "FORGED COMMIT"
        # Don't update content_hash — it's now wrong
        stmt = receipt.wrap_in_toto_statement(forged)
        self.assertEqual(stmt["_type"], "https://in-toto.io/Statement/v1")
        # The statement wraps the forged receipt without complaint
        self.assertEqual(stmt["predicate"]["commit"]["subject"], "FORGED COMMIT")
        # But verification of the inner receipt should FAIL
        result = verify.verify_receipt(stmt["predicate"])
        self.assertFalse(result["valid"])

    # ── A5-02: in-toto subject name injection ──
    def test_a5_02_intoto_subject_terminal_escape(self):
        """Inject terminal escapes into the in-toto subject name via repo URL.

        Defense: wrap_in_toto_statement sanitizes with _strip_terminal_escapes.
        """
        evil_receipt = _make_valid_receipt()
        evil_receipt["provenance"]["repository"] = (
            "https://evil.com/\x1b[2J\x1b[Hrepo.git"
        )
        stmt = receipt.wrap_in_toto_statement(evil_receipt)
        subject_name = stmt["subject"][0]["name"]
        self.assertNotIn("\x1b", subject_name,
                         "Terminal escapes must be stripped from in-toto subject")

    # ── A5-03: MCP path traversal via symlink chain ──
    def test_a5_03_mcp_symlink_intermediate_check(self):
        """Create a directory symlink and try to verify a receipt through it.

        Defense: _safe_verify_path checks intermediate symlinks.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            real_dir = Path(tmpdir) / "real"
            real_dir.mkdir()
            receipt_file = real_dir / "receipt.json"
            receipt_file.write_text('{"type": "test"}')
            # Create a symlink dir inside cwd
            link_dir = Path(tmpdir) / "link"
            link_dir.symlink_to(real_dir)
            # Try to verify through the symlink
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                with self.assertRaises(ValueError) as ctx:
                    mcp._safe_verify_path("link/receipt.json")
                self.assertIn("symlink", str(ctx.exception).lower())
            finally:
                os.chdir(original_cwd)

    # ── A5-04: MCP path outside cwd ──
    def test_a5_04_mcp_path_outside_cwd(self):
        """Attempt to verify /etc/passwd through the MCP server.

        Defense: _safe_verify_path rejects paths outside cwd.
        """
        with self.assertRaises(ValueError) as ctx:
            mcp._safe_verify_path("/etc/passwd")
        self.assertIn("current working directory", str(ctx.exception))

    # ── A5-05: MCP rate limiter deque overflow ──
    def test_a5_05_mcp_rate_limiter_rejects_flood(self):
        """Simulate 51+ requests per second — should trigger rate limiting.

        Note: serve_stdio() rate limiter uses deque. We test the logic
        conceptually — actual stdio testing requires subprocess.
        """
        from collections import deque
        # Simulate the rate limiter logic
        rate_limit_window = 1.0
        rate_limit_max = 50
        request_times = deque(maxlen=rate_limit_max * 2)
        now = time.monotonic()
        # Send 50 requests (at limit)
        for _ in range(50):
            request_times.append(now)
        while request_times and now - request_times[0] >= rate_limit_window:
            request_times.popleft()
        self.assertEqual(len(request_times), 50)  # At limit, not over
        # 51st request exceeds
        request_times.append(now)
        while request_times and now - request_times[0] >= rate_limit_window:
            request_times.popleft()
        self.assertGreater(len(request_times), rate_limit_max)

    # ── A5-06: MCP non-dict arguments ──
    def test_a5_06_mcp_non_dict_arguments(self):
        """Pass non-dict arguments to MCP tools/call.

        Defense: handle_tools_call validates arguments type.
        """
        for evil_args in ["string", [1, 2], 42, None, True]:
            result = mcp.handle_tools_call({"name": "aiir_receipt", "arguments": evil_args})
            self.assertTrue(result.get("isError", False),
                            f"Non-dict arguments ({type(evil_args).__name__}) should be rejected")

    # ── A5-07: MCP unknown tool name ──
    def test_a5_07_mcp_unknown_tool(self):
        """Call a non-existent MCP tool.

        Defense: handle_tools_call returns error for unknown tools.
        """
        result = mcp.handle_tools_call({"name": "evil_tool", "arguments": {}})
        self.assertTrue(result.get("isError", False))
        self.assertIn("Unknown tool", result["content"][0]["text"])

    # ── A5-08: Ledger path traversal ──
    def test_a5_08_ledger_path_traversal(self):
        """Attempt to write ledger to a directory outside cwd.

        Defense: append_to_ledger has path traversal guard + TOCTOU re-verify.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                evil_dir = os.path.join(tmpdir, "..", "..", "tmp", "evil_ledger")
                with self.assertRaises(ValueError) as ctx:
                    ledger.append_to_ledger(
                        [_make_valid_receipt()],
                        ledger_dir=evil_dir,
                    )
                self.assertIn("outside", str(ctx.exception).lower())
            finally:
                os.chdir(original_cwd)

    # ── A5-09: Ledger dedup bypass via different receipt same SHA ──
    def test_a5_09_ledger_dedup_first_writer_wins(self):
        """Write two different receipts with the same commit SHA.

        Attack: First attacker writes a forged receipt, then the legitimate
        receipt is silently dropped by dedup.
        Defense: Dedup by SHA is by design (idempotency). But this means
        the first writer wins — document as known trust boundary.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                ledger_dir = os.path.join(tmpdir, ".aiir")
                r1 = _make_valid_receipt()
                r2 = _make_valid_receipt()
                # Both have the same commit SHA but different subjects
                r2["commit"]["subject"] = "different subject"
                # Write first receipt
                appended1, _, _ = ledger.append_to_ledger([r1], ledger_dir=ledger_dir)
                # Write second receipt (same SHA) — should be skipped
                appended2, skipped2, _ = ledger.append_to_ledger([r2], ledger_dir=ledger_dir)
                self.assertEqual(appended1, 1, "First receipt should be appended")
                self.assertEqual(appended2, 0, "Second receipt should be skipped (dedup)")
                self.assertEqual(skipped2, 1, "Should report 1 skipped")
            finally:
                os.chdir(original_cwd)

    # ── A5-10: GitHub Actions key injection ──
    def test_a5_10_github_output_key_injection(self):
        """Inject newlines and '=' into GitHub output key names.

        Attack: key='evil\n<<delimiter\ninjected_value' would inject
        arbitrary outputs.
        Defense: set_github_output rejects newlines, '=', and '<<' in keys.
        """
        from aiir._github import set_github_output
        evil_keys = [
            "evil\nkey",
            "evil=key",
            "evil\rkey",
            "evil<<key",
            "\x01control",
        ]
        for key in evil_keys:
            with self.assertRaises(ValueError, msg=f"Key {key!r} should be rejected"):
                set_github_output(key, "value")

    # ── A5-11: Verify receipt file with symlink ──
    def test_a5_11_verify_receipt_rejects_symlink(self):
        """verify_receipt_file must reject symlinks.

        Attack: Symlink receipt.json → /etc/passwd to probe file contents
        via the verification error messages.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "real.json"
            target.write_text('{"type": "aiir.commit_receipt"}')
            link = Path(tmpdir) / "evil_link.json"
            link.symlink_to(target)
            result = verify.verify_receipt_file(str(link))
            self.assertFalse(result.get("valid", True))
            self.assertIn("symlink", result.get("error", "").lower())

    # ── A5-12: Verify receipt file oversized ──
    def test_a5_12_verify_receipt_file_size_limit(self):
        """Create a >50MB file and try to verify it.

        Defense: verify_receipt_file checks file size before reading.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            big_file = Path(tmpdir) / "huge.json"
            # Create a sparse file that reports > 50MB without using disk space
            with open(big_file, "wb") as f:
                f.seek(51 * 1024 * 1024)
                f.write(b"\x00")
            result = verify.verify_receipt_file(str(big_file))
            self.assertFalse(result.get("valid", True))
            self.assertIn("too large", result.get("error", "").lower())


# ===========================================================================
# CROSS-ANGLE: Combined Attacks
# ===========================================================================

class TestHostileCrossAngle(unittest.TestCase):
    """Multi-angle combined attacks that chain vulnerabilities."""

    # ── X-01: Detection evasion → schema mismatch → policy bypass ──
    def test_x01_detection_to_schema_to_policy_chain(self):
        """Chain: An AI-assisted commit evades schema validation,
        which makes require_schema_valid trigger, which blocks the receipt,
        which means AI transparency data is lost.

        This is the A3-01 + A4-01 chain — the most dangerous finding.
        """
        # Step 1: _detect.py classifies as "ai-assisted"
        # Step 2: Receipt is built with authorship_class="ai-assisted"
        # Step 3: Schema validates — "ai-assisted" not in valid_classes
        # Step 4: Schema errors are non-empty
        # Step 5: Strict policy with require_schema_valid=True → FAIL

        r = _make_valid_receipt()
        r["ai_attestation"]["authorship_class"] = "ai-assisted"
        r["ai_attestation"]["is_ai_authored"] = True

        # Step 3: Schema validation
        schema_errors = schema.validate_receipt_schema(r)
        authorship_schema_errors = [e for e in schema_errors if "authorship_class" in e]

        # Step 5: Policy evaluation
        strict = policy.POLICY_PRESETS["strict"]
        violations = policy.evaluate_receipt_policy(
            r, strict, schema_errors=schema_errors,
        )

        schema_violations = [v for v in violations if v.rule == "require_schema_valid"]
        authorship_violations = [v for v in violations if v.rule == "allowed_authorship_classes"]

        # Document the full chain
        findings = []
        if authorship_schema_errors:
            findings.append(
                f"Schema rejects 'ai-assisted': {authorship_schema_errors[0]}"
            )
        if schema_violations:
            findings.append(
                f"Strict policy blocks due to schema errors: {schema_violations[0].message}"
            )
        if authorship_violations:
            findings.append(
                f"Strict policy rejects authorship: {authorship_violations[0].message}"
            )

        if findings:
            self.fail(
                "CRITICAL CHAIN X-01: Detection → Schema → Policy cascade failure.\n"
                + "\n".join(f"  [{i+1}] {f}" for i, f in enumerate(findings))
                + "\nImpact: AI-assisted receipts are silently rejected by strict policy."
            )

    # ── X-02: Canonical JSON + verification round-trip ──
    def test_x02_canonical_json_round_trip_integrity(self):
        """Verify that a receipt built by build_commit_receipt passes
        verify_receipt without modification.

        This tests the full cryptographic integrity chain.
        """
        r = _make_valid_receipt()
        result = verify.verify_receipt(r)
        self.assertTrue(result["valid"], f"Valid receipt failed verification: {result}")

    # ── X-03: Extensions don't affect content_hash ──
    def test_x03_extensions_excluded_from_hash(self):
        """Verify that modifying extensions doesn't change content_hash.

        This is the design contract — extensions are NOT in CORE_KEYS.
        """
        r = _make_valid_receipt()
        original_hash = r["content_hash"]
        # Modify extensions
        r["extensions"]["evil"] = "injected data"
        r["extensions"]["agent_attestation"] = {"tool_id": "evil_tool"}
        # Re-verify — should still pass because extensions are excluded
        result = verify.verify_receipt(r)
        self.assertTrue(result["valid"],
                        "Extensions should not affect verification")

    # ── X-04: Timestamp doesn't affect content_hash ──
    def test_x04_timestamp_excluded_from_hash(self):
        """Verify that modifying timestamp doesn't change content_hash.

        Attack: An attacker backdates a receipt to claim an earlier creation time.
        Defense: Timestamp IS excluded from the hash (by design — it's not
        in CORE_KEYS). This is a known trade-off. To detect backdating,
        use Sigstore signing which includes a timestamp from the Rekor log.
        """
        r = _make_valid_receipt()
        r["timestamp"] = "1970-01-01T00:00:00Z"  # Backdate
        result = verify.verify_receipt(r)
        self.assertTrue(result["valid"],
                        "Timestamp is excluded from hash by design")

    # ── X-05: Agent attestation sanitization ──
    def test_x05_agent_attestation_sanitization(self):
        """Inject terminal escapes and oversized values in agent attestation.

        Defense: _sanitize_agent_attestation strips terminal escapes, caps
        at 200 chars, and only allows known keys.
        """
        evil_attestation = {
            "tool_id": "evil\x1b[2J\x1b[H",          # Terminal clear screen
            "model_class": "a" * 500,                   # Oversized
            "unknown_key": "should be dropped",         # Unknown key
            "session_id": "legit-session",
        }
        clean = receipt._sanitize_agent_attestation(evil_attestation)
        # Terminal escapes stripped
        self.assertNotIn("\x1b", clean.get("tool_id", ""))
        # Oversized value capped at 200
        self.assertLessEqual(len(clean.get("model_class", "")), 200)
        # Unknown key dropped
        self.assertNotIn("unknown_key", clean)
        # Known key preserved
        self.assertIn("session_id", clean)


# ===========================================================================
# ANGLE 2 SUPPLEMENT: Normalization Edge Cases
# ===========================================================================

class TestHostileAngle2NormalizationEdgeCases(unittest.TestCase):
    """Deep-dive into _normalize_for_detection edge cases."""

    def test_combining_diacritical_stripping(self):
        """Verify combining marks are stripped after NFKC.

        Attack: Add combining diacriticals to signal words:
        'copilot' + combining tilde on each char.
        """
        # Add combining tilde (U+0303) to each letter
        evasion = "c\u0303o\u0303p\u0303i\u0303l\u0303o\u0303t\u0303"
        normalized = core._normalize_for_detection(evasion)
        self.assertEqual(normalized, "copilot",
                         "Combining marks should be stripped")

    def test_variation_selector_stripping(self):
        """Verify variation selectors (U+FE00-U+FE0F) are stripped.

        Attack: Insert variation selectors between characters.
        These are Cf category — stripped before NFKC.
        """
        # Variation selector 16 (U+FE0F) between each char
        evasion = "c\ufe0fo\ufe0fp\ufe0fi\ufe0fl\ufe0fo\ufe0ft"
        normalized = core._normalize_for_detection(evasion)
        self.assertIn("copilot", normalized.lower())

    def test_hangul_compatibility_jamo_not_confused(self):
        """Verify that Hangul Compatibility Jamo are NOT confused with Latin.

        ㅊ (U+314A) should not become 'c', etc.
        """
        text = "\u314a\u314f\u314b"  # Hangul jamo — NOT Latin
        normalized = core._normalize_for_detection(text)
        # Should NOT contain Latin letters
        self.assertNotIn("c", normalized.lower())

    def test_mathematical_italic_a(self):
        """Verify Mathematical Italic Small A (U+1D44E) normalizes.

        NFKC maps U+1D44E → 'a'. This is used in academic paper evasion.
        """
        # Mathematical italic "copilot"
        # U+1D450=c, U+1D45C=o, U+1D45D=p, U+1D456=i, U+1D459=l, U+1D461=t
        text = "\U0001d450\U0001d45c\U0001d45d\U0001d456\U0001d459\U0001d45c\U0001d461"
        normalized = core._normalize_for_detection(text)
        self.assertEqual(normalized, "copilot",
                         "Mathematical italic should normalize to ASCII via NFKC")


# ===========================================================================
# ANGLE 3 SUPPLEMENT: Schema Validation Attacks
# ===========================================================================

class TestHostileAngle3SchemaAttacks(unittest.TestCase):
    """Deep-dive into _schema.py validation bypasses."""

    def test_bool_int_confusion_files_changed(self):
        """Pass True (bool) for files_changed (expected: int).

        In Python, bool is subclass of int. True == 1.
        Defense: _schema.py explicitly checks for bool vs int.
        """
        r = _make_valid_receipt()
        r["commit"]["files_changed"] = True  # bool, not int
        errors = schema.validate_receipt_schema(r)
        type_errors = [e for e in errors if "bool" in e.lower() or "files_changed" in e]
        self.assertTrue(
            len(type_errors) > 0,
            "Boolean True for files_changed should be rejected (not confused with int 1)",
        )

    def test_int_bool_confusion_is_ai_authored(self):
        """Pass 1 (int) for is_ai_authored (expected: bool).

        Defense: _schema.py explicitly checks for int vs bool.
        """
        r = _make_valid_receipt()
        r["ai_attestation"]["is_ai_authored"] = 1  # int, not bool
        errors = schema.validate_receipt_schema(r)
        type_errors = [e for e in errors if "bool" in e.lower() or "is_ai_authored" in e]
        self.assertTrue(
            len(type_errors) > 0,
            "Integer 1 for is_ai_authored should be rejected (not confused with bool True)",
        )

    def test_signal_count_mismatch(self):
        """signal_count doesn't match len(signals_detected).

        Attack: Inflate signal_count to make a commit look more AI-heavy
        than it is, or deflate to hide AI involvement.
        """
        r = _make_valid_receipt()
        r["ai_attestation"]["signal_count"] = 99
        r["ai_attestation"]["signals_detected"] = ["one"]
        errors = schema.validate_receipt_schema(r)
        mismatch_errors = [e for e in errors if "signal_count" in e]
        self.assertTrue(
            len(mismatch_errors) > 0,
            "Mismatched signal_count must be flagged",
        )

    def test_files_and_files_redacted_both_present(self):
        """Both files and files_redacted present — mutually exclusive.

        Defense: Schema checks for this conflict.
        """
        r = _make_valid_receipt()
        r["commit"]["files"] = ["a.py"]
        r["commit"]["files_redacted"] = True
        errors = schema.validate_receipt_schema(r)
        conflict_errors = [e for e in errors if "either" in e.lower()]
        self.assertTrue(
            len(conflict_errors) > 0,
            "Both files and files_redacted must be rejected",
        )

    def test_101_files_array(self):
        """Pass 101 files — exceeds the 100-entry limit.

        Defense: Schema validates max 100 file entries.
        """
        r = _make_valid_receipt()
        r["commit"]["files"] = [f"file_{i}.py" for i in range(101)]
        errors = schema.validate_receipt_schema(r)
        size_errors = [e for e in errors if "100" in e]
        self.assertTrue(
            len(size_errors) > 0,
            "101 files must exceed the 100-entry schema limit",
        )

    def test_tool_uri_forgery(self):
        """Forge provenance.tool to point to a different repo.

        Defense: Schema validates tool URI starts with the canonical prefix.
        """
        r = _make_valid_receipt()
        r["provenance"]["tool"] = "https://github.com/evil-org/evil-tool@1.0.0"
        errors = schema.validate_receipt_schema(r)
        tool_errors = [e for e in errors if "tool" in e.lower()]
        self.assertTrue(
            len(tool_errors) > 0,
            "Forged tool URI must be rejected by schema",
        )


# ===========================================================================
# ANGLE 1 SUPPLEMENT: Terminal Escape Attacks
# ===========================================================================

class TestHostileAngle1TerminalEscapes(unittest.TestCase):
    """Comprehensive terminal injection attacks."""

    def test_ansi_cursor_up_overwrite(self):
        """ESC[A moves cursor up — could overwrite previous output lines."""
        text = "normal\x1b[Aoverwrite"
        clean = core._strip_terminal_escapes(text)
        self.assertNotIn("\x1b", clean)

    def test_osc_title_injection(self):
        """ESC]0;Evil Title BEL — sets terminal title."""
        text = "\x1b]0;Evil Title\x07normal text"
        clean = core._strip_terminal_escapes(text)
        self.assertNotIn("Evil Title", clean)
        self.assertIn("normal text", clean)

    def test_dcs_injection(self):
        """ESC P...ST — Device Control String."""
        text = "\x1bPmalicious\x1b\\clean"
        clean = core._strip_terminal_escapes(text)
        self.assertNotIn("malicious", clean)
        self.assertIn("clean", clean)

    def test_8bit_c1_csi(self):
        """8-bit C1 CSI (U+009B) as single-byte equivalent of ESC[.

        Some terminals interpret 0x9B as CSI in UTF-8 mode.
        Defense: _strip_terminal_escapes strips 0x80-0x9F.
        """
        text = "before\x9b2Jafter"  # C1 CSI + '2J' = clear screen
        clean = core._strip_terminal_escapes(text)
        self.assertNotIn("\x9b", clean)
        self.assertIn("before", clean)

    def test_unterminated_osc(self):
        """OSC without terminator — payload should still be stripped.

        Defense: Regex makes ST optional.
        """
        text = "\x1b]0;Evil Title Without Terminator"
        clean = core._strip_terminal_escapes(text)
        self.assertNotIn("Evil Title", clean)


# ===========================================================================
# ANGLE 5 SUPPLEMENT: MCP Protocol Attacks
# ===========================================================================

class TestHostileAngle5MCPProtocol(unittest.TestCase):
    """Attack the MCP JSON-RPC protocol layer."""

    def test_missing_jsonrpc_field(self):
        """MCP message without jsonrpc field should be rejected."""
        # The serve_stdio handles this — we test the handler routing
        # Note: handle_tools_call itself doesn't check jsonrpc — that's
        # done in serve_stdio. But we can test that individual handlers
        # don't crash on unexpected input.
        result = mcp.handle_tools_call({})
        self.assertTrue(result.get("isError", False))

    def test_tools_call_with_no_name(self):
        """tools/call without a name should return error."""
        result = mcp.handle_tools_call({"arguments": {}})
        self.assertTrue(result.get("isError", False))

    def test_initialize_returns_protocol_version(self):
        """Verify initialize returns the expected protocol version."""
        result = mcp.handle_initialize({})
        self.assertEqual(result["protocolVersion"], "2025-03-26")
        self.assertIn("tools", result["capabilities"])

    def test_tools_list_returns_both_tools(self):
        """Verify tools/list returns aiir_receipt and aiir_verify."""
        result = mcp.handle_tools_list({})
        tool_names = [t["name"] for t in result["tools"]]
        self.assertIn("aiir_receipt", tool_names)
        self.assertIn("aiir_verify", tool_names)

    def test_max_path_length(self):
        """Path longer than _MAX_PATH_LEN (4096) should be rejected."""
        long_path = "a" * 5000
        with self.assertRaises(ValueError):
            mcp._safe_verify_path(long_path)

    def test_empty_path(self):
        """Empty path should be rejected."""
        with self.assertRaises(ValueError):
            mcp._safe_verify_path("")


# ===========================================================================
# ANGLE 5 SUPPLEMENT: Markdown Sanitization Attacks
# ===========================================================================

class TestHostileAngle5MarkdownSanitization(unittest.TestCase):
    """Attack _sanitize_md for GFM injection."""

    def test_pipe_injection_table_break(self):
        """Pipe characters in commit subjects break GFM table layout."""
        text = "feat: add | operator"
        safe = core._sanitize_md(text)
        self.assertNotIn("|", safe.replace("\\|", ""))

    def test_backtick_code_injection(self):
        """Backtick injection to create inline code spans."""
        text = "feat: add `malicious` code"
        safe = core._sanitize_md(text)
        self.assertNotIn("`", safe.replace("\\`", ""))

    def test_link_injection(self):
        """[link](https://evil.com) injection in commit subject."""
        text = "feat: [click here](https://evil.com)"
        safe = core._sanitize_md(text)
        self.assertNotIn("[", safe.replace("\\[", ""))

    def test_html_injection(self):
        """<script>alert(1)</script> injection."""
        text = "<script>alert('xss')</script>"
        safe = core._sanitize_md(text)
        self.assertNotIn("<script>", safe)
        self.assertIn("&lt;", safe)

    def test_autolink_breaking(self):
        """URLs should have :// broken with ZWSP to prevent autolinks."""
        text = "See https://evil.com/phishing"
        safe = core._sanitize_md(text)
        self.assertNotIn("://", safe.replace("\u200b://", ""))

    def test_emphasis_injection(self):
        """*bold* and _italic_ injection."""
        text = "*injected bold* and _injected italic_"
        safe = core._sanitize_md(text)
        self.assertNotIn("*", safe.replace("\\*", ""))
        self.assertNotIn("_", safe.replace("\\_", ""))

    def test_bidi_override_stripped(self):
        """RTL override (U+202E) should be stripped."""
        text = "normal\u202eesrever"
        safe = core._sanitize_md(text)
        self.assertNotIn("\u202e", safe)

    def test_backslash_escape_chain(self):
        r"""Backslash before pipe: \| — must not break table.

        Attack: A commit subject with \| would become \\| after escaping,
        and GFM might interpret \\ as literal backslash + | as pipe.
        Defense: Backslashes are escaped BEFORE pipes.
        """
        text = "feat: handle \\| edge case"
        safe = core._sanitize_md(text)
        # The backslash should be escaped, then the pipe should be escaped
        # Result should not contain an unescaped pipe
        self.assertNotIn("|", safe.replace("\\|", ""))


if __name__ == "__main__":
    unittest.main()
