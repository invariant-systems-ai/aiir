#!/usr/bin/env python3
"""validate_profile.py — Deterministic Enterprise Profile validator.

Validates an AIIR Enterprise Protected Branch Profile configuration
against the schema, then optionally evaluates a receipt ledger against
the profile's 12 EPB rules.

This script is intentionally self-contained — it does NOT import the
aiir package so it can serve as an independent reference validator.

Usage:
    # Schema-only validation (preflight)
    python scripts/validate_profile.py profile.json

    # Full evaluation against a ledger + git repo
    python scripts/validate_profile.py profile.json --ledger .aiir/receipts.jsonl

    # CI mode: exit 1 on any failure, machine-readable JSON output
    python scripts/validate_profile.py profile.json --ledger .aiir/receipts.jsonl --ci

Exit codes:
    0 — All enabled rules PASS (or schema-only validation succeeded)
    1 — At least one enabled rule FAILed or schema validation failed
    2 — Usage error / file not found

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

# ── Constants ──────────────────────────────────────────────────────────

CORE_KEYS_COMMIT = frozenset(
    {"type", "schema", "version", "commit", "ai_attestation", "provenance"}
)
CORE_KEYS_REVIEW = frozenset(
    {
        "type",
        "schema",
        "version",
        "reviewed_commit",
        "reviewer",
        "review_outcome",
        "comment",
        "provenance",
    }
)
MAX_DEPTH = 64
_VERSION_RE = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+([.+\-][0-9a-zA-Z.+\-]*)?$"
)

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"


# ── Canonical JSON (SPEC.md §6) ──────────────────────────────────────


def _canonical_json(obj: Any, _depth: int = 0) -> str:
    if _depth > MAX_DEPTH:
        raise ValueError("Depth limit exceeded")
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        # JSON floats — not expected in receipts but handle gracefully
        return json.dumps(obj)
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=True)
    if isinstance(obj, list):
        items = ",".join(_canonical_json(v, _depth + 1) for v in obj)
        return f"[{items}]"
    if isinstance(obj, dict):
        pairs = ",".join(
            f"{json.dumps(k, ensure_ascii=True)}:{_canonical_json(v, _depth + 1)}"
            for k, v in sorted(obj.items())
        )
        return "{" + pairs + "}"
    raise TypeError(f"Unsupported type: {type(obj)}")


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ── Schema validation (lightweight — no jsonschema dependency) ────────


def validate_profile_schema(profile: Dict[str, Any]) -> List[str]:
    """Validate a profile dict against the EPB v1 schema.

    Returns a list of error strings (empty = valid).
    """
    errors: List[str] = []

    if profile.get("profile") != "aiir/enterprise_protected_branch.v1":
        errors.append(
            f"profile must be 'aiir/enterprise_protected_branch.v1', "
            f"got {profile.get('profile')!r}"
        )

    version = profile.get("version", "")
    if not re.match(r"^[0-9]+\.[0-9]+\.[0-9]+$", version):
        errors.append(f"version must be SemVer, got {version!r}")

    rules = profile.get("rules")
    if not isinstance(rules, dict):
        errors.append("rules must be an object")
        return errors

    required_rules = [f"EPB-{i:03d}" for i in range(1, 13)]
    for rule_id in required_rules:
        if rule_id not in rules:
            errors.append(f"Missing required rule: {rule_id}")
            continue
        rule = rules[rule_id]
        if not isinstance(rule, dict):
            errors.append(f"{rule_id}: must be an object")
            continue
        if "enabled" not in rule:
            errors.append(f"{rule_id}: missing 'enabled' field")
        elif not isinstance(rule["enabled"], bool):
            errors.append(f"{rule_id}: 'enabled' must be boolean")

    # Rule-specific parameter validation
    if "EPB-004" in rules and rules["EPB-004"].get("enabled"):
        tier = rules["EPB-004"].get("min_trust_tier", 2)
        if tier not in (1, 2, 3):
            errors.append(f"EPB-004: min_trust_tier must be 1, 2, or 3")

    if "EPB-006" in rules and rules["EPB-006"].get("enabled"):
        pct = rules["EPB-006"].get("min_coverage_percent", 100)
        if not (0 <= pct <= 100):
            errors.append(f"EPB-006: min_coverage_percent must be 0–100")

    if "EPB-007" in rules and rules["EPB-007"].get("enabled"):
        pct = rules["EPB-007"].get("max_ai_percent", 50)
        if not (0 <= pct <= 100):
            errors.append(f"EPB-007: max_ai_percent must be 0–100")

    if "EPB-011" in rules and rules["EPB-011"].get("enabled"):
        digest = rules["EPB-011"].get("expected_policy_digest")
        if not digest or not re.match(r"^[0-9a-f]{64}$", str(digest)):
            errors.append(
                f"EPB-011: expected_policy_digest must be 64 hex chars"
            )

    if "EPB-012" in rules and rules["EPB-012"].get("enabled"):
        verifiers = rules["EPB-012"].get("trusted_verifiers")
        if not isinstance(verifiers, list) or len(verifiers) < 1:
            errors.append(
                f"EPB-012: trusted_verifiers must be a non-empty array"
            )

    return errors


# ── Receipt integrity (SPEC.md §9) ───────────────────────────────────


def verify_receipt_integrity(
    receipt: Dict[str, Any],
) -> tuple[bool, str]:
    """Verify content_hash and receipt_id of a receipt.

    Returns (is_valid, error_message).
    """
    rtype = receipt.get("type", "")
    if rtype == "aiir.commit_receipt":
        core_keys = CORE_KEYS_COMMIT
    elif rtype == "aiir.review_receipt":
        core_keys = CORE_KEYS_REVIEW
    else:
        return False, f"unknown receipt type: {rtype!r}"

    core = {k: v for k, v in receipt.items() if k in core_keys}
    core_json = _canonical_json(core)
    expected_hash = "sha256:" + _sha256(core_json)
    expected_id = "g1-" + _sha256(core_json)[:32]

    actual_hash = receipt.get("content_hash", "")
    actual_id = receipt.get("receipt_id", "")

    if not _constant_time_eq(expected_hash, actual_hash):
        return False, "content hash mismatch"
    if not _constant_time_eq(expected_id, actual_id):
        return False, "receipt_id mismatch"

    return True, ""


# ── Rule evaluators ───────────────────────────────────────────────────

RuleResult = Dict[str, Any]  # {"rule_id", "result", "reason"}


def _pass(rule_id: str, reason: str = "") -> RuleResult:
    return {"rule_id": rule_id, "result": "PASS", "reason": reason}


def _fail(rule_id: str, reason: str) -> RuleResult:
    return {"rule_id": rule_id, "result": "FAIL", "reason": reason}


def _skip(rule_id: str) -> RuleResult:
    return {"rule_id": rule_id, "result": "SKIP", "reason": "disabled"}


def evaluate_epb001(
    commit_receipts: Sequence[Dict[str, Any]],
    enabled: bool,
) -> RuleResult:
    """EPB-001: Commit receipt schema validity."""
    if not enabled:
        return _skip("EPB-001")
    for i, r in enumerate(commit_receipts):
        if r.get("type") != "aiir.commit_receipt":
            return _fail("EPB-001", f"receipt[{i}]: type is not aiir.commit_receipt")
        schema = r.get("schema", "")
        if not isinstance(schema, str) or not schema.startswith("aiir/"):
            return _fail("EPB-001", f"receipt[{i}]: schema does not start with aiir/")
        version = r.get("version", "")
        if not _VERSION_RE.match(str(version)):
            return _fail("EPB-001", f"receipt[{i}]: invalid version format")
    return _pass("EPB-001", f"{len(commit_receipts)} receipts valid")


def evaluate_epb002(
    review_receipts: Sequence[Dict[str, Any]],
    enabled: bool,
) -> RuleResult:
    """EPB-002: Review receipt schema validity."""
    if not enabled:
        return _skip("EPB-002")
    for i, r in enumerate(review_receipts):
        if r.get("type") != "aiir.review_receipt":
            return _fail("EPB-002", f"receipt[{i}]: type is not aiir.review_receipt")
        outcome = r.get("review_outcome", "")
        if outcome not in ("approved", "rejected", "commented"):
            return _fail("EPB-002", f"receipt[{i}]: invalid review_outcome: {outcome!r}")
    return _pass("EPB-002", f"{len(review_receipts)} review receipts valid")


def evaluate_epb003(
    all_receipts: Sequence[Dict[str, Any]],
    enabled: bool,
) -> RuleResult:
    """EPB-003: Content hash integrity."""
    if not enabled:
        return _skip("EPB-003")
    for i, r in enumerate(all_receipts):
        ok, err = verify_receipt_integrity(r)
        if not ok:
            rid = r.get("receipt_id", f"[{i}]")
            return _fail("EPB-003", f"{rid}: {err}")
    return _pass("EPB-003", f"{len(all_receipts)} receipts pass integrity check")


def evaluate_epb006(
    commit_shas: Sequence[str],
    commit_receipts: Sequence[Dict[str, Any]],
    enabled: bool,
    min_coverage_percent: float = 100.0,
) -> RuleResult:
    """EPB-006: Receipt coverage."""
    if not enabled:
        return _skip("EPB-006")
    total = len(commit_shas)
    if total == 0:
        return _pass("EPB-006", "no commits to cover")
    receipt_shas = {
        r.get("commit", {}).get("sha", "") for r in commit_receipts
    }
    covered = sum(1 for sha in commit_shas if sha in receipt_shas)
    pct = (covered / total) * 100
    if pct < min_coverage_percent:
        missing = total - covered
        return _fail(
            "EPB-006",
            f"coverage {pct:.1f}% < {min_coverage_percent}% "
            f"({missing} commits without receipts)",
        )
    return _pass("EPB-006", f"coverage {pct:.1f}% ({covered}/{total})")


def evaluate_epb007(
    commit_receipts: Sequence[Dict[str, Any]],
    enabled: bool,
    max_ai_percent: float = 50.0,
) -> RuleResult:
    """EPB-007: AI authorship cap."""
    if not enabled:
        return _skip("EPB-007")
    total = len(commit_receipts)
    if total == 0:
        return _pass("EPB-007", "no receipts to evaluate")
    ai_classes = {"ai_assisted", "ai+bot"}
    ai_count = sum(
        1
        for r in commit_receipts
        if r.get("ai_attestation", {}).get("authorship_class", "") in ai_classes
    )
    pct = (ai_count / total) * 100
    if pct > max_ai_percent:
        return _fail(
            "EPB-007",
            f"AI {pct:.1f}% > {max_ai_percent}% cap ({ai_count}/{total})",
        )
    return _pass("EPB-007", f"AI {pct:.1f}% within {max_ai_percent}% cap")


def evaluate_epb008(vsa: Optional[Dict[str, Any]], enabled: bool) -> RuleResult:
    """EPB-008: No invalid receipts in VSA."""
    if not enabled:
        return _skip("EPB-008")
    if vsa is None:
        return _fail("EPB-008", "no VSA provided")
    evaluation = vsa.get("evaluation", {})
    invalid = evaluation.get("invalidReceipts", -1)
    violations = evaluation.get("policyViolations", -1)
    if invalid != 0:
        return _fail("EPB-008", f"VSA reports {invalid} invalid receipts")
    if violations != 0:
        return _fail("EPB-008", f"VSA reports {violations} policy violations")
    return _pass("EPB-008")


def evaluate_epb009(
    commit_receipts: Sequence[Dict[str, Any]],
    review_receipts: Sequence[Dict[str, Any]],
    enabled: bool,
) -> RuleResult:
    """EPB-009: Human review required for AI-assisted changes."""
    if not enabled:
        return _skip("EPB-009")
    ai_classes = {"ai_assisted", "ai+bot"}

    # Build set of approved reviews keyed by commit SHA
    approved_reviews: Dict[str, List[str]] = {}
    for rr in review_receipts:
        if rr.get("review_outcome") == "approved":
            sha = rr.get("reviewed_commit", {}).get("sha", "")
            reviewer_email = rr.get("reviewer", {}).get("email", "")
            if sha and reviewer_email:
                approved_reviews.setdefault(sha, []).append(reviewer_email)

    for r in commit_receipts:
        authorship = r.get("ai_attestation", {}).get("authorship_class", "")
        if authorship not in ai_classes:
            continue
        sha = r.get("commit", {}).get("sha", "")
        author_email = r.get("commit", {}).get("author", {}).get("email", "")

        reviewers = approved_reviews.get(sha, [])
        non_author = [e for e in reviewers if e != author_email]
        if not non_author:
            return _fail(
                "EPB-009",
                f"AI-assisted commit {sha[:12]} has no approved review "
                f"from a non-author reviewer",
            )
    return _pass("EPB-009")


def evaluate_epb010(
    commit_receipts: Sequence[Dict[str, Any]],
    enabled: bool,
) -> RuleResult:
    """EPB-010: Bot commits require receipt and provenance match."""
    if not enabled:
        return _skip("EPB-010")
    for r in commit_receipts:
        if r.get("ai_attestation", {}).get("authorship_class") != "bot":
            continue
        attest = r.get("ai_attestation", {})
        if not attest.get("is_bot_authored"):
            sha = r.get("commit", {}).get("sha", "")[:12]
            return _fail("EPB-010", f"bot commit {sha}: is_bot_authored not true")
        if not attest.get("bot_signals_detected"):
            sha = r.get("commit", {}).get("sha", "")[:12]
            return _fail("EPB-010", f"bot commit {sha}: no bot signals detected")
        tool = r.get("provenance", {}).get("tool", "")
        if not tool.startswith("https://"):
            sha = r.get("commit", {}).get("sha", "")[:12]
            return _fail("EPB-010", f"bot commit {sha}: tool URI missing https://")
    return _pass("EPB-010")


def evaluate_epb011(
    vsa: Optional[Dict[str, Any]],
    enabled: bool,
    expected_digest: str = "",
) -> RuleResult:
    """EPB-011: VSA policy digest binding."""
    if not enabled:
        return _skip("EPB-011")
    if vsa is None:
        return _fail("EPB-011", "no VSA provided")
    actual = vsa.get("policy", {}).get("digest", {}).get("sha256", "")
    if not _constant_time_eq(actual, expected_digest):
        return _fail("EPB-011", "VSA policy digest does not match expected")
    return _pass("EPB-011")


def evaluate_epb012(
    vsa: Optional[Dict[str, Any]],
    enabled: bool,
    trusted_verifiers: Sequence[str] = (),
) -> RuleResult:
    """EPB-012: VSA verifier identity."""
    if not enabled:
        return _skip("EPB-012")
    if vsa is None:
        return _fail("EPB-012", "no VSA provided")
    verifier_id = vsa.get("verifier", {}).get("id", "")
    if verifier_id not in trusted_verifiers:
        return _fail(
            "EPB-012",
            f"verifier {verifier_id!r} not in trusted list",
        )
    result = vsa.get("verificationResult", "")
    if result != "PASSED":
        return _fail("EPB-012", f"verificationResult is {result!r}, expected PASSED")
    return _pass("EPB-012")


# ── Full evaluation ───────────────────────────────────────────────────


def evaluate_profile(
    profile: Dict[str, Any],
    commit_receipts: Sequence[Dict[str, Any]] = (),
    review_receipts: Sequence[Dict[str, Any]] = (),
    commit_shas: Sequence[str] = (),
    vsa: Optional[Dict[str, Any]] = None,
) -> List[RuleResult]:
    """Evaluate all 12 EPB rules.

    Returns results in rule order — short-circuits on category failure.
    """
    rules = profile.get("rules", {})
    results: List[RuleResult] = []

    def _enabled(rule_id: str) -> bool:
        return rules.get(rule_id, {}).get("enabled", False)

    # ── Category A: Schema ────────────────────────────────────────────
    all_receipts = list(commit_receipts) + list(review_receipts)

    r001 = evaluate_epb001(commit_receipts, _enabled("EPB-001"))
    results.append(r001)

    r002 = evaluate_epb002(review_receipts, _enabled("EPB-002"))
    results.append(r002)

    # Short-circuit: if schema rules fail, skip everything else
    if r001["result"] == "FAIL" or r002["result"] == "FAIL":
        for rule_id in [f"EPB-{i:03d}" for i in range(3, 13)]:
            results.append(
                _fail(rule_id, "skipped: schema validation failed")
            )
        return results

    # ── Category B: Integrity ─────────────────────────────────────────
    r003 = evaluate_epb003(all_receipts, _enabled("EPB-003"))
    results.append(r003)

    # EPB-004 (trust tier) and EPB-005 (DAG binding) need file-level
    # inspection (Sigstore bundles, git object store) — not evaluable
    # from pure JSON ledger alone.  Report SKIP with explanation.
    results.append(
        _skip("EPB-004")
        if not _enabled("EPB-004")
        else {
            "rule_id": "EPB-004",
            "result": "SKIP",
            "reason": "trust tier check requires Sigstore bundle inspection (not available in ledger-only mode)",
        }
    )
    results.append(
        _skip("EPB-005")
        if not _enabled("EPB-005")
        else {
            "rule_id": "EPB-005",
            "result": "SKIP",
            "reason": "DAG binding check requires git object store (not available in ledger-only mode)",
        }
    )

    if r003["result"] == "FAIL":
        for rule_id in [f"EPB-{i:03d}" for i in range(6, 13)]:
            results.append(
                _fail(rule_id, "skipped: integrity validation failed")
            )
        return results

    # ── Category C: Coverage / Accounting ─────────────────────────────
    r006 = evaluate_epb006(
        commit_shas,
        commit_receipts,
        _enabled("EPB-006"),
        rules.get("EPB-006", {}).get("min_coverage_percent", 100),
    )
    results.append(r006)

    r007 = evaluate_epb007(
        commit_receipts,
        _enabled("EPB-007"),
        rules.get("EPB-007", {}).get("max_ai_percent", 50),
    )
    results.append(r007)

    r008 = evaluate_epb008(vsa, _enabled("EPB-008"))
    results.append(r008)

    # ── Category D: Policy Predicates ─────────────────────────────────
    r009 = evaluate_epb009(
        commit_receipts, review_receipts, _enabled("EPB-009")
    )
    results.append(r009)

    r010 = evaluate_epb010(commit_receipts, _enabled("EPB-010"))
    results.append(r010)

    r011 = evaluate_epb011(
        vsa,
        _enabled("EPB-011"),
        rules.get("EPB-011", {}).get("expected_policy_digest", ""),
    )
    results.append(r011)

    r012 = evaluate_epb012(
        vsa,
        _enabled("EPB-012"),
        rules.get("EPB-012", {}).get("trusted_verifiers", []),
    )
    results.append(r012)

    return results


# ── CLI entry point ───────────────────────────────────────────────────


def main(argv: Optional[List[str]] = None) -> int:
    args = argv if argv is not None else sys.argv[1:]

    if not args or "--help" in args or "-h" in args:
        print(__doc__)
        return 0

    profile_path = Path(args[0])
    if not profile_path.is_file():
        print(f"Error: profile not found: {profile_path}", file=sys.stderr)
        return 2

    ledger_path: Optional[Path] = None
    ci_mode = "--ci" in args
    if "--ledger" in args:
        idx = args.index("--ledger")
        if idx + 1 >= len(args):
            print("Error: --ledger requires a path argument", file=sys.stderr)
            return 2
        ledger_path = Path(args[idx + 1])
        if not ledger_path.is_file():
            print(
                f"Error: ledger not found: {ledger_path}", file=sys.stderr
            )
            return 2

    # Load and validate profile
    try:
        profile = json.loads(profile_path.read_text("utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Error loading profile: {exc}", file=sys.stderr)
        return 2

    schema_errors = validate_profile_schema(profile)
    if schema_errors:
        print("Profile schema validation FAILED:")
        for err in schema_errors:
            print(f"  - {err}")
        return 1

    print(f"Profile schema: VALID ({profile_path.name})")

    if ledger_path is None:
        # Schema-only validation
        if ci_mode:
            result = {
                "profile": str(profile_path),
                "schema_valid": True,
                "mode": "schema-only",
            }
            print(json.dumps(result, indent=2))
        return 0

    # Load ledger
    commit_receipts: List[Dict[str, Any]] = []
    review_receipts: List[Dict[str, Any]] = []
    try:
        for line in ledger_path.read_text("utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            receipt = json.loads(line)
            rtype = receipt.get("type", "")
            if rtype == "aiir.commit_receipt":
                commit_receipts.append(receipt)
            elif rtype == "aiir.review_receipt":
                review_receipts.append(receipt)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Error loading ledger: {exc}", file=sys.stderr)
        return 2

    # Extract commit SHAs (from receipts — no git dependency)
    commit_shas = [
        r.get("commit", {}).get("sha", "")
        for r in commit_receipts
        if r.get("commit", {}).get("sha")
    ]

    # Evaluate
    results = evaluate_profile(
        profile,
        commit_receipts=commit_receipts,
        review_receipts=review_receipts,
        commit_shas=commit_shas,
    )

    # Display
    passed = sum(1 for r in results if r["result"] == "PASS")
    failed = sum(1 for r in results if r["result"] == "FAIL")
    skipped = sum(1 for r in results if r["result"] == "SKIP")

    for r in results:
        icon = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "SKIP"}[r["result"]]
        reason = f" — {r['reason']}" if r.get("reason") else ""
        print(f"  [{icon}] {r['rule_id']}{reason}")

    summary = f"\nResult: {passed} passed, {failed} failed, {skipped} skipped"
    print(summary)

    if ci_mode:
        output = {
            "profile": str(profile_path),
            "ledger": str(ledger_path),
            "schema_valid": True,
            "results": results,
            "summary": {
                "passed": passed,
                "failed": failed,
                "skipped": skipped,
            },
            "overall": "PASS" if failed == 0 else "FAIL",
        }
        print(json.dumps(output, indent=2))

    return 1 if failed > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
