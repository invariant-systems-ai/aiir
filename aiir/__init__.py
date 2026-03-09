"""
AIIR — AI Integrity Receipts

Generate cryptographic receipts for commits with declared AI involvement.
Zero dependencies — uses only Python standard library.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

__version__ = "1.1.0"

# ---------------------------------------------------------------------------
# Public API — importable via `from aiir import ...`
# ---------------------------------------------------------------------------

from aiir._core import _canonical_json, _sha256  # noqa: F401
from aiir._detect import detect_ai_signals  # noqa: F401
from aiir._explain import explain_verification  # noqa: F401
from aiir._ledger import append_to_ledger, export_ledger  # noqa: F401
from aiir._policy import (
    evaluate_ledger_policy,
    evaluate_receipt_policy,
    load_policy,
    POLICY_PRESETS,
)  # noqa: F401
from aiir._receipt import (
    generate_receipt,
    generate_receipts_for_range,
    format_receipt_pretty,
    wrap_in_toto_statement,
)  # noqa: F401
from aiir._schema import validate_receipt_schema as validate_receipt  # noqa: F401
from aiir._stats import check_policy, format_badge, format_stats  # noqa: F401
from aiir._verify import verify_receipt, verify_receipt_file  # noqa: F401
from aiir._gitlab import (  # noqa: F401
    format_gitlab_summary,
    format_gl_sast_report,
    generate_dashboard_html,
    parse_webhook_event,
    validate_webhook_token,
    build_receipts_graphql_query,
)

__all__ = [
    "__version__",
    # Receipt generation
    "generate_receipt",
    "generate_receipts_for_range",
    "format_receipt_pretty",
    "wrap_in_toto_statement",
    # Detection
    "detect_ai_signals",
    # Verification
    "verify_receipt",
    "verify_receipt_file",
    "explain_verification",
    # Schema
    "validate_receipt",
    # Ledger
    "append_to_ledger",
    "export_ledger",
    # Stats & policy
    "format_badge",
    "format_stats",
    "check_policy",
    "load_policy",
    "evaluate_receipt_policy",
    "evaluate_ledger_policy",
    "POLICY_PRESETS",
    # GitLab integration
    "format_gitlab_summary",
    "format_gl_sast_report",
    "generate_dashboard_html",
    "parse_webhook_event",
    "validate_webhook_token",
    "build_receipts_graphql_query",
    # Low-level (for third-party implementors)
    "_canonical_json",
    "_sha256",
]
