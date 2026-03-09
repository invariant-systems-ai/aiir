"""
AIIR internal — release-scoped verification and Verification Summary Attestation.

Evaluates a bundle of AIIR receipts (from a ledger or files) against a named
policy and emits a pass/fail decision as a signed Verification Summary
Attestation (VSA).  This is the "policy decision engine" layer that turns
raw commit receipts into trusted decisions consumable by CI gates, auditors,
GRC platforms, and insurers.

Design follows the SLSA Verification Summary Attestation pattern:
  - A verifier identifies itself.
  - Names the policy.
  - Records input attestations (receipts).
  - Emits a pass/fail decision that downstream users can rely on.

Zero external dependencies — uses only Python standard library + aiir internals.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from aiir._core import (
    CLI_VERSION,
    MAX_RECEIPT_FILE_SIZE,
    _canonical_json,
    _now_rfc3339,
    _run_git,
    _sha256,
    _strip_url_credentials,
    _validate_ref,
    logger,
)
from aiir._detect import list_commits_in_range
from aiir._policy import (
    PolicyViolation,
    evaluate_receipt_policy,
    load_policy,
)
from aiir._schema import validate_receipt_schema
from aiir._verify import verify_receipt

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VSA_PREDICATE_TYPE = (
    "https://invariantsystems.io/predicates/aiir/verification_summary/v1"
)

VERIFIER_ID = "https://invariantsystems.io/verifiers/aiir"

# Maximum receipts to load from a ledger file (DoS prevention).
_MAX_LEDGER_RECEIPTS = 50_000

# Maximum policy file size (1 MB).
_MAX_POLICY_FILE_SIZE = 1 * 1024 * 1024


# ---------------------------------------------------------------------------
# Receipt loading
# ---------------------------------------------------------------------------


def _load_receipts_from_ledger(ledger_path: str) -> List[Dict[str, Any]]:
    """Load receipts from a JSONL ledger file.

    Returns a list of parsed receipt dicts.  Skips malformed lines.
    """
    path = Path(ledger_path)
    if not path.is_file():
        raise FileNotFoundError(f"Ledger not found: {ledger_path}")
    if path.is_symlink():
        raise ValueError(f"Ledger is a symlink (refusing to read): {ledger_path}")
    try:
        file_size = path.stat().st_size
    except OSError as e:
        raise ValueError(f"Cannot stat ledger: {e}") from e
    if file_size > MAX_RECEIPT_FILE_SIZE:
        raise ValueError(
            f"Ledger too large ({file_size} bytes, max {MAX_RECEIPT_FILE_SIZE})"
        )

    receipts: List[Dict[str, Any]] = []
    for line_num, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = line.strip()
        if not line:
            continue
        if len(receipts) >= _MAX_LEDGER_RECEIPTS:
            logger.warning(
                "Ledger truncated at %d receipts (safety limit)", _MAX_LEDGER_RECEIPTS
            )
            break
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                receipts.append(obj)
        except json.JSONDecodeError:
            logger.warning("Skipping malformed line %d in %s", line_num, ledger_path)
    return receipts


def _load_receipts_from_dir(receipt_dir: str) -> List[Dict[str, Any]]:
    """Load receipts from individual JSON files in a directory."""
    dirpath = Path(receipt_dir)
    if not dirpath.is_dir():
        raise FileNotFoundError(f"Receipt directory not found: {receipt_dir}")

    receipts: List[Dict[str, Any]] = []
    for fpath in sorted(dirpath.glob("*.json")):
        if fpath.is_symlink():
            continue
        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                receipts.append(data)
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        receipts.append(item)
        except (json.JSONDecodeError, OSError):
            logger.warning("Skipping unreadable file: %s", fpath.name)
    return receipts


def _load_receipts(receipts_path: str) -> List[Dict[str, Any]]:
    """Load receipts from a ledger file (JSONL) or a directory of JSON files."""
    p = Path(receipts_path)
    if p.is_dir():
        return _load_receipts_from_dir(receipts_path)
    elif p.is_file():
        return _load_receipts_from_ledger(receipts_path)
    else:
        raise FileNotFoundError(f"Receipts path not found: {receipts_path}")


# ---------------------------------------------------------------------------
# Coverage calculation
# ---------------------------------------------------------------------------


def _compute_coverage(
    commit_shas: List[str],
    receipts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute receipt coverage for a set of commits.

    Returns a dict with coverage stats:
      - commits_total: total commits in range
      - receipts_found: how many commits have a matching receipt
      - receipts_missing: list of commit SHAs without receipts
      - coverage_percent: 0..100.0
    """
    # Build a set of commit SHAs that have receipts.
    receipted_shas = set()
    for r in receipts:
        commit = r.get("commit", {})
        if isinstance(commit, dict):
            sha = commit.get("sha", "")
            if sha:
                receipted_shas.add(sha)

    total = len(commit_shas)
    found = sum(1 for sha in commit_shas if sha in receipted_shas)
    missing = [sha for sha in commit_shas if sha not in receipted_shas]

    return {
        "commits_total": total,
        "receipts_found": found,
        "receipts_missing": missing,
        "coverage_percent": round(found / total * 100, 1) if total > 0 else 100.0,
    }


# ---------------------------------------------------------------------------
# Per-receipt verification + policy evaluation
# ---------------------------------------------------------------------------


def _evaluate_receipts(
    receipts: List[Dict[str, Any]],
    policy: Dict[str, Any],
    *,
    commit_shas: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Verify and evaluate each receipt against policy.

    Returns a summary dict with:
      - total_receipts: count
      - valid_receipts: receipts that pass integrity check
      - invalid_receipts: receipts that fail integrity check
      - policy_violations: list of all violations
      - receipts_by_commit: map sha -> evaluation result
    """
    # If commit_shas provided, only evaluate receipts for those commits.
    scope_shas = set(commit_shas) if commit_shas else None

    total = 0
    valid_count = 0
    invalid_count = 0
    all_violations: List[Dict[str, Any]] = []
    receipts_by_commit: Dict[str, Dict[str, Any]] = {}

    allowed_methods = policy.get("allowed_detection_methods")
    disallow_unsigned_ext = policy.get("disallow_unsigned_extensions", False)

    for receipt in receipts:
        commit = receipt.get("commit", {})
        if not isinstance(commit, dict):
            continue
        sha = commit.get("sha", "")
        if not sha:
            continue
        if scope_shas is not None and sha not in scope_shas:
            continue

        total += 1

        # 1) Content integrity verification
        vresult = verify_receipt(receipt)
        is_valid = vresult.get("valid", False)
        if is_valid:
            valid_count += 1
        else:
            invalid_count += 1

        # 2) Schema validation
        schema_errors = validate_receipt_schema(receipt)

        # 3) Policy evaluation
        # Determine signing status from receipt (check for sigstore bundle ref)
        is_signed = bool(receipt.get("extensions", {}).get("sigstore_bundle"))
        violations = evaluate_receipt_policy(
            receipt,
            policy,
            is_signed=is_signed,
            schema_errors=schema_errors,
        )

        # 4) Extra policy constraints: allowed detection methods
        if allowed_methods:
            ai = receipt.get("ai_attestation", {})
            if isinstance(ai, dict):
                method = ai.get("detection_method", "")
                if method and method not in allowed_methods:
                    violations.append(
                        PolicyViolation(
                            rule="allowed_detection_methods",
                            message=(
                                f"Detection method '{method}' not in allowed list: "
                                f"{allowed_methods}"
                            ),
                            severity="error",
                        )
                    )

        # 5) Extra policy constraint: disallow unsigned extensions
        if disallow_unsigned_ext and not is_signed:
            extensions = receipt.get("extensions", {})
            if isinstance(extensions, dict) and extensions:
                # Check for non-empty extensions beyond standard keys.
                ext_keys = set(extensions.keys()) - {
                    "sigstore_bundle",
                    "generator",
                    "instance_id",
                }
                if ext_keys:
                    violations.append(
                        PolicyViolation(
                            rule="disallow_unsigned_extensions",
                            message=(
                                f"Unsigned receipt has extension keys {sorted(ext_keys)} — "
                                f"policy requires signing when extensions are present"
                            ),
                            severity="error",
                        )
                    )

        violation_dicts = [v.to_dict() for v in violations]
        all_violations.extend([{**vd, "commit_sha": sha} for vd in violation_dicts])

        receipts_by_commit[sha] = {
            "valid": is_valid,
            "errors": vresult.get("errors", []),
            "schema_errors": schema_errors or [],
            "policy_violations": violation_dicts,
            "is_signed": is_signed,
        }

    return {
        "total_receipts": total,
        "valid_receipts": valid_count,
        "invalid_receipts": invalid_count,
        "policy_violations": all_violations,
        "receipts_by_commit": receipts_by_commit,
    }


# ---------------------------------------------------------------------------
# Verification Summary Attestation builder
# ---------------------------------------------------------------------------


def _build_vsa_predicate(
    *,
    policy: Dict[str, Any],
    policy_uri: str,
    policy_digest: str,
    input_receipts_uri: str,
    input_receipts_digest: str,
    verification_result: str,
    coverage: Dict[str, Any],
    evaluation: Dict[str, Any],
    commit_range: Optional[str] = None,
    time_verified: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the VSA predicate body."""
    constraints: Dict[str, Any] = {}
    if policy.get("require_signing"):
        constraints["requireSigned"] = True
    if policy.get("allowed_detection_methods"):
        constraints["allowedDetectionMethods"] = policy["allowed_detection_methods"]
    if policy.get("disallow_unsigned_extensions"):
        constraints["disallowUnsignedExtensions"] = True
    if policy.get("allowed_authorship_classes"):
        constraints["allowedAuthorshipClasses"] = policy["allowed_authorship_classes"]
    if policy.get("max_ai_percent") is not None:
        constraints["maxAiPercent"] = policy["max_ai_percent"]

    predicate: Dict[str, Any] = {
        "verifier": {
            "id": VERIFIER_ID,
            "version": {"aiir": CLI_VERSION},
        },
        "timeVerified": time_verified or _now_rfc3339(),
        "policy": {
            "uri": policy_uri,
            "digest": {"sha256": policy_digest},
        },
        "inputAttestations": [
            {
                "uri": input_receipts_uri,
                "digest": {"sha256": input_receipts_digest},
            }
        ],
        "verificationResult": verification_result,
        "coverage": {
            "commitRange": commit_range or "",
            "commitsTotal": coverage["commits_total"],
            "receiptsFound": coverage["receipts_found"],
            "receiptsMissing": len(coverage["receipts_missing"]),
            "coveragePercent": coverage["coverage_percent"],
        },
        "evaluation": {
            "totalReceipts": evaluation["total_receipts"],
            "validReceipts": evaluation["valid_receipts"],
            "invalidReceipts": evaluation["invalid_receipts"],
            "policyViolations": len(evaluation["policy_violations"]),
        },
    }
    if constraints:
        predicate["constraints"] = constraints
    return predicate


def _wrap_vsa_in_toto(
    predicate: Dict[str, Any],
    subject_name: str,
    subject_digest: Dict[str, str],
) -> Dict[str, Any]:
    """Wrap a VSA predicate in an in-toto Statement v1 envelope."""
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": subject_name,
                "digest": subject_digest,
            }
        ],
        "predicateType": VSA_PREDICATE_TYPE,
        "predicate": predicate,
    }


# ---------------------------------------------------------------------------
# Public API: verify_release
# ---------------------------------------------------------------------------


def verify_release(
    *,
    commit_range: Optional[str] = None,
    receipts_path: str = ".aiir/receipts.jsonl",
    policy_path: Optional[str] = None,
    policy_preset: Optional[str] = None,
    subject_name: Optional[str] = None,
    subject_digest: Optional[Dict[str, str]] = None,
    emit_intoto: bool = False,
    cwd: Optional[str] = None,
    policy_overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Verify a release by evaluating receipts against policy.

    This is the core "policy decision engine" function. It:
    1. Loads receipts from a ledger or directory.
    2. Lists commits in the specified range (if given).
    3. Computes coverage (which commits have receipts).
    4. Verifies each receipt's integrity.
    5. Evaluates each receipt against policy.
    6. Produces a PASS/FAIL decision.
    7. Optionally wraps the decision as an in-toto VSA.

    Args:
        commit_range: Git range (e.g., 'origin/main..HEAD'). If None, all
            receipts are evaluated without a commit-range constraint.
        receipts_path: Path to ledger (JSONL) or directory of receipt JSONs.
        policy_path: Path to policy JSON file. Mutually exclusive with
            policy_preset.
        policy_preset: Policy preset name ('strict', 'balanced', 'permissive').
        subject_name: Subject identifier for the VSA (e.g., OCI image ref).
        subject_digest: Subject digest for the VSA (e.g., {'sha256': '...'}).
        emit_intoto: If True, wrap the result as an in-toto Statement.
        cwd: Working directory for git operations (defaults to os.getcwd()).
        policy_overrides: Extra policy keys to merge on top of loaded policy.

    Returns:
        A dict with the verification result. If emit_intoto=True, returns
        an in-toto Statement v1 wrapping the VSA predicate.
    """
    # 1) Load policy
    if policy_path:
        p = Path(policy_path)
        if not p.is_file():
            raise FileNotFoundError(f"Policy file not found: {policy_path}")
        if p.is_symlink():
            raise ValueError(f"Policy is a symlink (refusing to load): {policy_path}")
        try:
            fsize = p.stat().st_size
        except OSError as e:
            raise ValueError(f"Cannot stat policy file: {e}") from e
        if fsize > _MAX_POLICY_FILE_SIZE:
            raise ValueError(
                f"Policy file too large ({fsize} bytes, max {_MAX_POLICY_FILE_SIZE})"
            )
        raw = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Policy file must be a JSON object")
        policy = raw
    elif policy_preset:
        policy = load_policy(preset=policy_preset)
    else:
        # Default: try .aiir/policy.json, fall back to balanced
        policy = load_policy()

    # Apply overrides
    if policy_overrides:
        policy = {**policy, **policy_overrides}

    # 2) Load receipts
    receipts = _load_receipts(receipts_path)
    if not receipts:
        return {
            "verificationResult": "FAILED",
            "reason": "No receipts found",
            "receipts_path": receipts_path,
        }

    # 3) Compute input digest (hash of the receipts content)
    receipts_raw = Path(receipts_path)
    if receipts_raw.is_file():
        receipts_content = receipts_raw.read_text(encoding="utf-8")
    else:
        # Directory — hash the canonical JSON of all loaded receipts
        receipts_content = _canonical_json(receipts)
    input_receipts_digest = _sha256(receipts_content)

    # 4) Get commit list (if range specified)
    commit_shas: List[str] = []
    if commit_range:
        # Validate range endpoints
        parts = commit_range.split("..")
        for part in parts:
            part = part.strip()
            if part:
                _validate_ref(part)
        commits = list_commits_in_range(commit_range, cwd=cwd)
        commit_shas = [c.sha for c in commits]

    # 5) Compute coverage
    if commit_shas:
        coverage = _compute_coverage(commit_shas, receipts)
    else:
        # No range → coverage is based on all receipts
        all_shas = []
        for r in receipts:
            c = r.get("commit", {})
            if isinstance(c, dict) and c.get("sha"):
                all_shas.append(c["sha"])
        coverage = {
            "commits_total": len(all_shas),
            "receipts_found": len(all_shas),
            "receipts_missing": [],
            "coverage_percent": 100.0,
        }

    # 6) Evaluate receipts
    evaluation = _evaluate_receipts(
        receipts,
        policy,
        commit_shas=commit_shas if commit_shas else None,
    )

    # 7) Determine pass/fail
    # Reasons for FAILED:
    #   - Any invalid receipts (integrity failure)
    #   - Any policy violations with severity="error"
    #   - Coverage below 100% (missing receipts for commits in range)
    error_violations = [
        v for v in evaluation["policy_violations"] if v.get("severity") == "error"
    ]
    has_integrity_failures = evaluation["invalid_receipts"] > 0
    has_policy_errors = len(error_violations) > 0
    has_coverage_gap = len(coverage.get("receipts_missing", [])) > 0

    enforcement = policy.get("enforcement", "warn")

    if has_integrity_failures:
        verification_result = "FAILED"
        reason = f"{evaluation['invalid_receipts']} receipt(s) failed integrity check"
    elif has_policy_errors and enforcement in ("hard-fail", "soft-fail"):
        verification_result = "FAILED"
        reason = f"{len(error_violations)} policy violation(s)"
    elif has_coverage_gap and enforcement in ("hard-fail", "soft-fail"):
        verification_result = "FAILED"
        missing_count = len(coverage["receipts_missing"])
        reason = f"{missing_count} commit(s) missing receipts"
    else:
        verification_result = "PASSED"
        reason = "All checks passed"

    # 8) Build policy digest
    policy_content = _canonical_json(policy)
    policy_digest = _sha256(policy_content)
    policy_uri = "inline://policy"
    if policy_path:
        policy_uri = str(policy_path)
    elif policy.get("preset"):
        policy_uri = f"aiir://presets/{policy['preset']}"

    # 9) Build the result
    time_verified = _now_rfc3339()

    predicate = _build_vsa_predicate(
        policy=policy,
        policy_uri=policy_uri,
        policy_digest=policy_digest,
        input_receipts_uri=str(receipts_path),
        input_receipts_digest=input_receipts_digest,
        verification_result=verification_result,
        coverage=coverage,
        evaluation=evaluation,
        commit_range=commit_range,
        time_verified=time_verified,
    )

    # Build full result
    result: Dict[str, Any] = {
        "verificationResult": verification_result,
        "reason": reason,
        "predicate": predicate,
        "policy_violations": evaluation["policy_violations"],
        "coverage": coverage,
    }

    # 10) Optionally wrap as in-toto Statement
    if emit_intoto:
        # Build subject from arguments or derive from git
        if not subject_name:
            try:
                remote = _run_git(["remote", "get-url", "origin"], cwd=cwd).strip()
                remote = _strip_url_credentials(remote)
            except (RuntimeError, FileNotFoundError):
                remote = "unknown"
            head_sha = ""
            if commit_range and ".." in commit_range:
                head_ref = commit_range.split("..")[-1].strip() or "HEAD"
                try:
                    head_sha = _run_git(["rev-parse", head_ref], cwd=cwd).strip()
                except (RuntimeError, FileNotFoundError):
                    head_sha = "unknown"
            else:
                try:
                    head_sha = _run_git(["rev-parse", "HEAD"], cwd=cwd).strip()
                except (RuntimeError, FileNotFoundError):
                    head_sha = "unknown"
            subject_name = f"{remote}@{head_sha}"

        if not subject_digest:
            # Derive from head commit SHA
            sha = subject_name.split("@")[-1] if "@" in subject_name else "unknown"
            subject_digest = {"gitCommit": sha}

        statement = _wrap_vsa_in_toto(predicate, subject_name, subject_digest)
        result["intoto_statement"] = statement

    return result


# ---------------------------------------------------------------------------
# Human-readable report
# ---------------------------------------------------------------------------


def format_release_report(result: Dict[str, Any]) -> str:
    """Format a verify-release result as a human-readable report."""
    lines: List[str] = []

    verdict = result.get("verificationResult", "UNKNOWN")
    reason = result.get("reason", "")

    lines.append(f"AIIR Release Verification: {verdict}")
    lines.append(f"Reason: {reason}")
    lines.append("")

    # Coverage
    cov = result.get("coverage", {})
    lines.append("Coverage:")
    lines.append(f"  Commits in range: {cov.get('commits_total', 0)}")
    lines.append(f"  Receipts found:   {cov.get('receipts_found', 0)}")
    missing = cov.get("receipts_missing", [])
    if missing:
        lines.append(f"  Missing receipts: {len(missing)}")
        for sha in missing[:10]:
            lines.append(f"    - {sha[:12]}")
        if len(missing) > 10:
            lines.append(f"    ... and {len(missing) - 10} more")
    lines.append(f"  Coverage:         {cov.get('coverage_percent', 0)}%")
    lines.append("")

    # Evaluation
    pred = result.get("predicate", {})
    ev = pred.get("evaluation", {})
    lines.append("Evaluation:")
    lines.append(f"  Receipts checked:   {ev.get('totalReceipts', 0)}")
    lines.append(f"  Valid (integrity):  {ev.get('validReceipts', 0)}")
    lines.append(f"  Invalid:            {ev.get('invalidReceipts', 0)}")
    lines.append(f"  Policy violations:  {ev.get('policyViolations', 0)}")
    lines.append("")

    # Violations
    violations = result.get("policy_violations", [])
    if violations:
        lines.append("Policy Violations:")
        for v in violations[:20]:
            sha = v.get("commit_sha", "")[:12]
            rule = v.get("rule", "")
            msg = v.get("message", "")
            lines.append(f"  [{sha}] {rule}: {msg}")
        if len(violations) > 20:
            lines.append(f"  ... and {len(violations) - 20} more")
        lines.append("")

    # Verifier
    verifier = pred.get("verifier", {})
    if verifier:
        lines.append(
            f"Verifier: {verifier.get('id', '')} "
            f"(aiir {verifier.get('version', {}).get('aiir', '')})"
        )

    return "\n".join(lines)
