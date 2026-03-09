"""
AIIR internal — policy engine.

Provides org-level policy presets (strict, balanced, permissive), policy
file loading (.aiir/policy.json), and staged enforcement modes
(warn → soft-fail → hard-fail).

Zero external dependencies — uses only Python standard library.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Policy presets
# ---------------------------------------------------------------------------

POLICY_PRESETS: Dict[str, Dict[str, Any]] = {
    "strict": {
        "description": "Enterprise / regulated — maximum assurance",
        "require_signing": True,
        "max_ai_percent": 50.0,
        "require_provenance_repo": True,
        "max_unsigned_receipts": 0,
        "require_schema_valid": True,
        "enforcement": "hard-fail",
        "allowed_authorship_classes": ["human", "ai_assisted"],
    },
    "balanced": {
        "description": "Standard team — practical defaults",
        "require_signing": False,
        "max_ai_percent": 80.0,
        "require_provenance_repo": False,
        "max_unsigned_receipts": -1,  # unlimited
        "require_schema_valid": False,
        "enforcement": "soft-fail",
        "allowed_authorship_classes": [
            "human",
            "ai_assisted",
            "ai_generated",
            "bot",
        ],
    },
    "permissive": {
        "description": "Open source / experimentation — minimum friction",
        "require_signing": False,
        "max_ai_percent": 100.0,
        "require_provenance_repo": False,
        "max_unsigned_receipts": -1,
        "require_schema_valid": False,
        "enforcement": "warn",
        "allowed_authorship_classes": [
            "human",
            "ai_assisted",
            "ai_generated",
            "bot",
            "ai+bot",
        ],
    },
}

ENFORCEMENT_LEVELS = ("warn", "soft-fail", "hard-fail")


# ---------------------------------------------------------------------------
# Policy loading and saving
# ---------------------------------------------------------------------------


def load_policy(
    ledger_dir: str = ".aiir",
    preset: Optional[str] = None,
) -> Dict[str, Any]:
    """Load policy from .aiir/policy.json, or fall back to a preset.

    Priority:
    1. If ``preset`` is given, return that preset (ignore file).
    2. If .aiir/policy.json exists, load and validate it.
    3. Otherwise, return the 'balanced' preset as default.
    """
    if preset:
        if preset not in POLICY_PRESETS:
            raise ValueError(
                f"Unknown policy preset: {preset!r}. "
                f"Choose from: {', '.join(POLICY_PRESETS)}"
            )
        return {**POLICY_PRESETS[preset], "preset": preset}

    policy_path = Path(ledger_dir) / "policy.json"
    if policy_path.exists() and policy_path.is_file():
        try:
            raw = json.loads(policy_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"Invalid policy file {policy_path}: {e}") from e
        if not isinstance(raw, dict):
            raise ValueError(f"Policy file must be a JSON object: {policy_path}")
        # If the file specifies a preset, start from that and overlay.
        base_preset = raw.get("preset")
        if base_preset and base_preset in POLICY_PRESETS:
            merged = {**POLICY_PRESETS[base_preset], **raw}
            return merged
        return raw

    # Default: balanced
    return {**POLICY_PRESETS["balanced"], "preset": "balanced"}


def save_policy(
    policy: Dict[str, Any],
    ledger_dir: str = ".aiir",
) -> str:
    """Save policy to .aiir/policy.json. Returns the path."""
    policy_path = Path(ledger_dir) / "policy.json"
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text(
        json.dumps(policy, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return str(policy_path)


def init_policy(
    preset: str = "balanced",
    ledger_dir: str = ".aiir",
) -> Tuple[Dict[str, Any], str]:
    """Initialize a policy file from a preset. Returns (policy, path)."""
    if preset not in POLICY_PRESETS:
        raise ValueError(
            f"Unknown policy preset: {preset!r}. "
            f"Choose from: {', '.join(POLICY_PRESETS)}"
        )
    policy = {**POLICY_PRESETS[preset], "preset": preset}
    path = save_policy(policy, ledger_dir)
    return policy, path


# ---------------------------------------------------------------------------
# Policy evaluation
# ---------------------------------------------------------------------------


class PolicyViolation:
    """A single policy violation with severity and actionable message."""

    __slots__ = ("rule", "message", "severity", "remediation")

    def __init__(
        self,
        rule: str,
        message: str,
        severity: str = "error",
        remediation: str = "",
    ):
        self.rule = rule
        self.message = message
        self.severity = severity  # "error" | "warning"
        self.remediation = remediation

    def to_dict(self) -> Dict[str, str]:
        d = {"rule": self.rule, "message": self.message, "severity": self.severity}
        if self.remediation:
            d["remediation"] = self.remediation
        return d


def evaluate_receipt_policy(
    receipt: Dict[str, Any],
    policy: Dict[str, Any],
    *,
    is_signed: bool = False,
    schema_errors: Optional[List[str]] = None,
) -> List[PolicyViolation]:
    """Evaluate a single receipt against a policy. Returns violations list.

    An empty list means the receipt passes all policy checks.
    """
    violations: List[PolicyViolation] = []
    enforcement = policy.get("enforcement", "warn")

    # 1. Signing requirement
    if policy.get("require_signing") and not is_signed:
        violations.append(
            PolicyViolation(
                rule="require_signing",
                message="Receipt is not signed. Policy requires Sigstore signing.",
                severity="error" if enforcement == "hard-fail" else "warning",
                remediation="Regenerate with: aiir --sign -o .receipts",
            )
        )

    # 2. Provenance repository
    if policy.get("require_provenance_repo"):
        prov = receipt.get("provenance", {})
        if not isinstance(prov, dict):
            prov = {}
        if not prov.get("repository"):
            violations.append(
                PolicyViolation(
                    rule="require_provenance_repo",
                    message="Receipt has no provenance repository. Policy requires a git remote.",
                    severity="error" if enforcement == "hard-fail" else "warning",
                    remediation="Configure a git remote: git remote add origin <url>",
                )
            )

    # 3. Allowed authorship classes
    allowed = policy.get("allowed_authorship_classes")
    if allowed:
        ai = receipt.get("ai_attestation", {})
        if not isinstance(ai, dict):
            ai = {}
        authorship = ai.get("authorship_class", "human")
        # Normalize legacy hyphenated forms (v1.0.4–v1.0.13) to canonical
        # underscore forms used by SPEC, schema, and policy presets.
        # Current _detect.py (v1.0.14+) emits canonical forms directly.
        _AUTHORSHIP_NORMALIZE = {
            "ai-assisted": "ai_assisted",
            "ai-generated": "ai_generated",
            "bot-generated": "bot",
        }
        authorship_normalized = _AUTHORSHIP_NORMALIZE.get(authorship, authorship)
        if authorship_normalized not in allowed and authorship not in allowed:
            violations.append(
                PolicyViolation(
                    rule="allowed_authorship_classes",
                    message=f"Authorship class '{authorship}' is not in the allowed list: {allowed}",
                    severity="error",
                    remediation="Review the commit for policy compliance, or update the policy.",
                )
            )

    # 4. Schema validity
    if policy.get("require_schema_valid") and schema_errors:
        violations.append(
            PolicyViolation(
                rule="require_schema_valid",
                message=f"Receipt has {len(schema_errors)} schema validation error(s).",
                severity="error" if enforcement == "hard-fail" else "warning",
                remediation="Fix the receipt to conform to schemas/commit_receipt.v1.schema.json.",
            )
        )

    return violations


def evaluate_ledger_policy(
    index: Dict[str, Any],
    policy: Dict[str, Any],
) -> Tuple[bool, str, List[PolicyViolation]]:
    """Evaluate ledger-level aggregate policy checks.

    Returns (passed, summary_message, violations).
    """
    violations: List[PolicyViolation] = []
    enforcement = policy.get("enforcement", "warn")

    # Max AI percentage
    max_ai = policy.get("max_ai_percent")
    if max_ai is not None:
        # Coerce to float to prevent TypeError from string/non-numeric values
        # in crafted policy files (red-team finding A4-07).
        try:
            max_ai = float(max_ai)
        except (TypeError, ValueError):
            max_ai = None
    if max_ai is not None:
        ai_pct = index.get("ai_percentage", 0.0)
        total = index.get("receipt_count", 0)
        if total > 0 and ai_pct > max_ai:
            violations.append(
                PolicyViolation(
                    rule="max_ai_percent",
                    message=(
                        f"AI-authored percentage {ai_pct}% exceeds policy maximum {max_ai}%"
                        f" ({index.get('ai_commit_count', 0)}/{total} commits)"
                    ),
                    severity="error",
                    remediation=(
                        "Increase human-authored commits, or raise the threshold"
                        " in .aiir/policy.json."
                    ),
                )
            )

    # Compose result
    if violations:
        if enforcement == "warn":
            return True, f"WARN: {len(violations)} policy warning(s)", violations
        elif enforcement == "soft-fail":
            return (
                False,
                f"SOFT-FAIL: {len(violations)} policy violation(s)",
                violations,
            )
        else:  # hard-fail
            return False, f"FAIL: {len(violations)} policy violation(s)", violations
    else:
        return True, "PASS: all policy checks passed", []


def format_policy_report(
    violations: List[PolicyViolation],
    enforcement: str = "warn",
) -> str:
    """Format policy violations as a human-readable report."""
    if not violations:
        return "All policy checks passed."

    lines = [
        f"Policy enforcement: {enforcement}",
        f"Violations: {len(violations)}",
        "",
    ]
    for i, v in enumerate(violations, 1):
        icon = "!" if v.severity == "error" else "~"
        lines.append(f"  [{icon}] {v.rule}: {v.message}")
        if v.remediation:
            lines.append(f"       Fix: {v.remediation}")
    return "\n".join(lines)
