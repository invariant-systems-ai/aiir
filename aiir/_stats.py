"""
AIIR internal — badge, stats dashboard, and policy checks.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from aiir._core import _USE_BOXDRAW


def format_badge(
    index: Dict[str, Any],
    namespace: Optional[str] = None,
) -> Dict[str, str]:
    """Generate a shields.io badge URL and Markdown snippet from ledger stats.

    Returns a dict with keys: url, markdown, text.
    """
    total = index.get("receipt_count", 0)
    ai_pct = index.get("ai_percentage", 0.0)
    # URL-encode the percent sign for shields.io.
    label = "AI Transparency"
    value = f"{ai_pct}%25 AI" if total > 0 else "no receipts"
    color = "blue" if total > 0 else "lightgrey"
    # shields.io static badge: label-value-color
    # Spaces → underscores, hyphens → double-dash per shields.io spec.
    safe_label = label.replace("-", "--").replace(" ", "_")
    safe_value = value.replace("-", "--").replace(" ", "_")
    url = f"https://img.shields.io/badge/{safe_label}-{safe_value}-{color}"
    md = f"[![{label}]({url})](https://github.com/invariant-systems-ai/aiir)"
    text = f"{label}: {ai_pct}% AI ({total} receipts)"
    return {"url": url, "markdown": md, "text": text}


def format_stats(
    index: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
) -> str:
    """Format a human-readable stats dashboard from the ledger index."""
    total = index.get("receipt_count", 0)
    ai_count = index.get("ai_commit_count", 0)
    ai_pct = index.get("ai_percentage", 0.0)
    authors = index.get("unique_authors", 0)
    first = index.get("first_receipt") or "—"
    latest = index.get("latest_timestamp") or "—"
    # Truncate timestamps to date for readability.
    if first and "T" in str(first):
        first = str(first).split("T")[0]
    if latest and "T" in str(latest):
        latest = str(latest).split("T")[0]
    ns = ""
    if config and config.get("namespace"):
        ns = f"  Namespace: {config['namespace']}\n"
    iid = ""
    if config and config.get("instance_id"):
        iid = f"  Instance:  {config['instance_id'][:8]}…\n"
    bar = "─" * 44 if _USE_BOXDRAW else "-" * 44
    return (
        f"{bar}\n"
        f"  AIIR Ledger — {total} receipt{'s' if total != 1 else ''}"
        f", {authors} author{'s' if authors != 1 else ''}\n"
        f"{bar}\n"
        f"  AI-authored:  {ai_count} commit{'s' if ai_count != 1 else ''}"
        f" ({ai_pct}%)\n"
        f"  First:        {first}\n"
        f"  Latest:       {latest}\n"
        f"{ns}"
        f"{iid}"
        f"{bar}"
    )


def check_policy(
    index: Dict[str, Any],
    *,
    max_ai_percent: Optional[float] = None,
) -> Tuple[bool, str]:
    """Evaluate policy gates against ledger stats.

    Returns (passed, message).  `passed` is True when all gates pass.
    """
    total = index.get("receipt_count", 0)
    if total == 0:
        return False, "No receipts found — run 'aiir' first to generate receipts."

    ai_pct = index.get("ai_percentage", 0.0)

    if max_ai_percent is not None:
        if ai_pct > max_ai_percent:
            return (
                False,
                f"FAIL: AI percentage {ai_pct}% exceeds threshold {max_ai_percent}%"
                f" ({index.get('ai_commit_count', 0)}/{total} commits)",
            )
        return (
            True,
            f"PASS: AI percentage {ai_pct}% within threshold {max_ai_percent}%"
            f" ({index.get('ai_commit_count', 0)}/{total} commits)",
        )

    return True, f"OK: {total} receipts, {ai_pct}% AI"
