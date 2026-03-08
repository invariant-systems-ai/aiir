"""
AIIR internal — receipt building, generation, formatting, and writing.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from aiir._core import (
    CLI_VERSION,
    RECEIPT_SCHEMA_VERSION,
    CommitInfo,
    _HAS_FCHMOD,
    _USE_BOXDRAW,
    _b,
    _canonical_json,
    _now_rfc3339,
    _run_git,
    _sha256,
    _strip_terminal_escapes,
    _strip_url_credentials,
    _validate_ref,
)
from aiir._detect import (
    detect_ai_signals,
    get_commit_info,
    list_commits_in_range,
)


def build_commit_receipt(
    commit: CommitInfo, repo_root: Optional[str] = None,
    redact_files: bool = False,
    instance_id: Optional[str] = None,
    namespace: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a cryptographic receipt for a git commit.

    The receipt is a content-addressed JSON object. The receipt_id is derived
    from the SHA-256 of the canonical JSON of the receipt core (everything
    except the receipt_id itself and the timestamp).
    """
    now = _now_rfc3339()

    # Determine repo identity (None when no remote configured)
    repo_url: Optional[str] = None
    try:
        repo_url = _run_git(
            ["remote", "get-url", "origin"], cwd=repo_root
        ).strip() or None
        if repo_url:
            repo_url = _strip_url_credentials(repo_url)
    except RuntimeError:
        pass

    # Build receipt core (everything that gets hashed)
    receipt_core = {
        "type": "aiir.commit_receipt",
        "schema": RECEIPT_SCHEMA_VERSION,
        "version": CLI_VERSION,
        "commit": {
            "sha": commit.sha,
            "author": {
                "name": commit.author_name,
                "email": commit.author_email,
                "date": commit.author_date,
            },
            "committer": {
                "name": commit.committer_name,
                "email": commit.committer_email,
                "date": commit.committer_date,
            },
            "subject": commit.subject,
            "message_hash": "sha256:" + _sha256(commit.body),
            "diff_hash": commit.diff_hash,
            "files_changed": len(commit.files_changed),
            # When --redact-files is set, omit individual file paths
            # to prevent internal project structure enumeration.
            **({"files": commit.files_changed[:100]} if not redact_files else {"files_redacted": True}),
            # Indicate when file list was truncated so verifiers know
            # the full list is not present.
            **({"files_capped": True} if not redact_files and len(commit.files_changed) > 100 else {}),
        },
        "ai_attestation": {
            "is_ai_authored": commit.is_ai_authored,
            "signals_detected": commit.ai_signals_detected,
            "signal_count": len(commit.ai_signals_detected),
            "is_bot_authored": commit.is_bot_authored,
            "bot_signals_detected": commit.bot_signals_detected,
            "bot_signal_count": len(commit.bot_signals_detected),
            "authorship_class": commit.authorship_class,
            "detection_method": "heuristic_v2",
        },
        "provenance": {
            "repository": repo_url,
            # URI-based tool identifier for SLSA/in-toto compatibility.
            "tool": f"https://github.com/invariant-systems-ai/aiir@{CLI_VERSION}",
            "generator": "aiir.cli",
        },
    }

    # Compute content-addressed receipt ID
    core_json = _canonical_json(receipt_core)
    content_hash = "sha256:" + _sha256(core_json)
    receipt_id = f"g1-{_sha256(core_json)[:32]}"

    # Final receipt = core + derived fields
    receipt = {
        **receipt_core,
        "receipt_id": receipt_id,
        "content_hash": content_hash,
        "timestamp": now,
        # Extension point for downstream integrations.
        # This field is NOT in CORE_KEYS and is excluded from
        # content_hash/receipt_id, so integrations can populate it
        # without breaking receipt verification.
        "extensions": {
            **(({"instance_id": instance_id}) if instance_id else {}),
            **(({"namespace": namespace}) if namespace else {}),
        },
    }

    return receipt


def generate_receipt(
    commit_ref: str = "HEAD",
    cwd: Optional[str] = None,
    ai_only: bool = False,
    redact_files: bool = False,
    instance_id: Optional[str] = None,
    namespace: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Generate a receipt for a single commit. Returns None if skipped."""
    _validate_ref(commit_ref)
    commit = get_commit_info(commit_ref, cwd=cwd)

    if ai_only and not commit.is_ai_authored:
        return None

    return build_commit_receipt(
        commit, repo_root=cwd, redact_files=redact_files,
        instance_id=instance_id, namespace=namespace,
    )


def generate_receipts_for_range(
    range_spec: str,
    cwd: Optional[str] = None,
    ai_only: bool = False,
    redact_files: bool = False,
    instance_id: Optional[str] = None,
    namespace: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Generate receipts for all commits in a range."""
    shas = list_commits_in_range(range_spec, cwd=cwd)
    receipts = []
    for sha in shas:
        receipt = generate_receipt(
            sha, cwd=cwd, ai_only=ai_only, redact_files=redact_files,
            instance_id=instance_id, namespace=namespace,
        )
        if receipt is not None:
            receipts.append(receipt)
    return receipts


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def format_receipt_pretty(receipt: Dict[str, Any]) -> str:
    """Human-readable receipt summary."""
    commit = receipt.get("commit", {})
    ai = receipt.get("ai_attestation", {})
    # Guard against non-dict commit/ai_attestation — a crafted
    # receipt with these fields as strings, lists, or ints would crash all
    # subsequent .get() calls with AttributeError.
    if not isinstance(commit, dict):
        commit = {}
    if not isinstance(ai, dict):
        ai = {}
    # Sanitize ALL user-controlled or display fields
    # against terminal escape injection.
    subject = _strip_terminal_escapes(commit.get('subject', ''))
    # Guard author sub-field type — extends defensive pattern to
    # nested fields.  A crafted receipt with author as string/int/list/None
    # would crash the .get('name', '') call with AttributeError.
    author = commit.get('author', {})
    if not isinstance(author, dict):
        author = {}
    author_name = _strip_terminal_escapes(author.get('name', ''))
    author_email = _strip_terminal_escapes(author.get('email', ''))
    receipt_id = _strip_terminal_escapes(str(receipt.get('receipt_id', 'unknown')))
    commit_sha = _strip_terminal_escapes(str(commit.get('sha', 'unknown'))[:12])
    content_hash = _strip_terminal_escapes(str(receipt.get('content_hash', '')))
    timestamp = _strip_terminal_escapes(str(receipt.get('timestamp', '')))
    # Coerce files_changed to int — a crafted receipt could
    # inject arbitrary strings via this field into terminal output.
    # Also catch OverflowError — int(float('inf')) raises
    # OverflowError, and json.loads('1e999') produces float('inf').
    try:
        files_count = int(commit.get('files_changed', 0))
    except (TypeError, ValueError, OverflowError):
        files_count = 0
    # Guard against non-list signals_detected — a crafted
    # receipt with signals_detected as a dict or string would crash on
    # slicing (dict[:3] raises TypeError).  Coerce to empty list.
    signals = ai.get('signals_detected', [])
    if not isinstance(signals, (list, tuple)):
        signals = []
    # Box-drawing chars → _b() for encoding safety.
    # Lazy-import cli._b so that tests toggling cli._USE_BOXDRAW are respected.
    from aiir.cli import _b as _box  # noqa: C0415 — lazy to avoid circular import
    tl, vl, bl, hl = _box("tl"), _box("vl"), _box("bl"), _box("hl")
    lines = [
        f"{tl}{hl} Receipt: {receipt_id}",
        f"{vl}  Commit:  {commit_sha}",
        f"{vl}  Subject: {subject}",
        f"{vl}  Author:  {author_name} <{author_email}>",
        f"{vl}  Files:   {files_count} changed",
        f"{vl}  AI:      {'YES' if ai.get('is_ai_authored') else 'no'}"
        + (
            # Sanitize signal strings — a crafted receipt could
            # inject ANSI escapes via signals_detected list items.
            # Also validate signal types and cap length — a crafted
            # receipt could smuggle long or non-string items into the output.
            # Use guarded `signals` (coerced to list above).
            f" ({', '.join(_strip_terminal_escapes(str(s))[:80] for s in signals[:3] if isinstance(s, (str, int, float)))})"
            if signals
            else ""
        ),
        f"{vl}  Hash:    {content_hash}",
        f"{vl}  Time:    {timestamp}",
        f"{bl}{hl * 42}",
    ]
    return "\n".join(lines)


def write_receipt(
    receipt: Dict[str, Any],
    output_dir: Optional[str] = None,
    jsonl: bool = False,
) -> str:
    """Write receipt to file or stdout. Returns the output path or 'stdout'."""
    receipt_json = json.dumps(receipt, indent=2, ensure_ascii=False)

    if output_dir:
        out_path = Path(output_dir).resolve()
        # Prevent path traversal — use relative_to (not startswith, which
        # has a prefix-collision bug: /repo vs /repo_evil both pass startswith).
        cwd_resolved = Path(os.getcwd()).resolve()
        try:
            out_path.relative_to(cwd_resolved)
        except ValueError:
            raise ValueError(
                f"output-dir must be within the working directory: {output_dir!r} "
                f"resolves outside {cwd_resolved}"
            )
        out_path.mkdir(parents=True, exist_ok=True)
        # Re-verify after mkdir to narrow TOCTOU/symlink race window
        real_out = out_path.resolve()
        try:
            real_out.relative_to(cwd_resolved)
        except ValueError:  # pragma: no cover — TOCTOU race
            raise ValueError(
                "output-dir escaped working directory after creation "
                "(possible symlink attack)"
            )
        commit_sha = receipt.get("commit", {}).get("sha", "unknown")[:12]
        commit_sha = re.sub(r'[^a-zA-Z0-9_-]', '_', commit_sha)
        # Deterministic filename from content_hash — makes it easy to
        # check if a receipt already exists for a given commit.
        chash = receipt.get("content_hash", "")
        chash_short = re.sub(r'[^a-fA-F0-9]', '', chash)[:16]
        filename = f"receipt_{commit_sha}_{chash_short}.json"
        filepath = out_path / filename
        # If this exact receipt already exists, return existing path
        if filepath.exists():
            return str(filepath)
        fd = os.open(str(filepath), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        # os.open mode is masked by umask — force 0o644 after creation
        if _HAS_FCHMOD:
            os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(receipt_json + "\n")
        return str(filepath)
    elif jsonl:
        # JSON Lines: one receipt per line, no pretty printing
        print(_canonical_json(receipt), flush=True)
        return "stdout:jsonl"
    else:
        print(receipt_json, flush=True)
        return "stdout:json"
