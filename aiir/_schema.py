"""
AIIR internal — receipt schema validation.

Validates receipt structure against the aiir/commit_receipt.v1 specification.
Zero external dependencies — uses only Python standard library.

This module is the structural validation layer. It checks types, required
fields, patterns, and constraints BEFORE content-hash verification runs.
This separation means a malformed receipt is rejected early with a clear
error instead of a confusing "hash mismatch" message.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Patterns (compiled once at import time)
# ---------------------------------------------------------------------------

_RE_SHA_HEX = re.compile(r"^[0-9a-f]{40,64}$")
_RE_HASH_PREFIX = re.compile(r"^sha256:[0-9a-f]{64}$")
_RE_VERSION = re.compile(r"^[0-9a-zA-Z.+\-]+$")
_RE_RECEIPT_ID = re.compile(r"^g1-[0-9a-f]{32}$")
_RE_CONTENT_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_RE_TOOL_URI = re.compile(r"^https://github\.com/invariant-systems-ai/aiir@")

# Maximum nesting depth before we reject (matches _core.py limit)
_MAX_DEPTH = 64


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_receipt_schema(receipt: Any) -> List[str]:
    """Validate a receipt dict against the aiir/commit_receipt.v1 schema.

    Returns a list of human-readable error strings.  An empty list means
    the receipt passes structural validation.

    This does NOT verify content_hash or receipt_id integrity — that is
    the responsibility of ``verify_receipt()`` in ``_verify.py``.
    """
    errors: List[str] = []

    if not isinstance(receipt, dict):
        return ["receipt is not a JSON object (dict)"]

    # ── Top-level required fields ──
    _require_field(receipt, "type", str, errors)
    _require_field(receipt, "schema", str, errors)
    _require_field(receipt, "version", str, errors)
    _require_field(receipt, "commit", dict, errors)
    _require_field(receipt, "ai_attestation", dict, errors)
    _require_field(receipt, "provenance", dict, errors)
    _require_field(receipt, "receipt_id", str, errors)
    _require_field(receipt, "content_hash", str, errors)
    _require_field(receipt, "timestamp", str, errors)
    _require_field(receipt, "extensions", dict, errors)

    # If core structure is broken, return early — deeper checks would NPE.
    if errors:
        return errors

    # ── Type and schema constants ──
    if receipt["type"] != "aiir.commit_receipt":
        errors.append(
            f"type must be 'aiir.commit_receipt', got {receipt['type']!r}"
        )
    if receipt["schema"] != "aiir/commit_receipt.v1":
        errors.append(
            f"schema must be 'aiir/commit_receipt.v1', got {receipt['schema']!r}"
        )

    # ── Version format ──
    if not _RE_VERSION.match(receipt["version"]):
        errors.append(
            f"version must match [0-9a-zA-Z.+-]+, got {receipt['version']!r}"
        )

    # ── receipt_id pattern ──
    if not _RE_RECEIPT_ID.match(receipt["receipt_id"]):
        errors.append(
            f"receipt_id must match 'g1-' + 32 hex chars, got {receipt['receipt_id']!r}"
        )

    # ── content_hash pattern ──
    if not _RE_CONTENT_HASH.match(receipt["content_hash"]):
        errors.append(
            f"content_hash must match 'sha256:' + 64 hex chars, got {receipt['content_hash']!r}"
        )

    # ── Commit object ──
    commit = receipt["commit"]
    _validate_commit(commit, errors)

    # ── AI attestation object ──
    ai = receipt["ai_attestation"]
    _validate_ai_attestation(ai, errors)

    # ── Provenance object ──
    prov = receipt["provenance"]
    _validate_provenance(prov, errors)

    # ── Extensions must be a dict (already checked above) ──
    # No further structural requirements — it's an open object.

    return errors


# ---------------------------------------------------------------------------
# Sub-validators
# ---------------------------------------------------------------------------

def _validate_commit(commit: Dict[str, Any], errors: List[str]) -> None:
    """Validate the commit sub-object."""
    prefix = "commit"

    # Required string fields
    _require_field(commit, "sha", str, errors, prefix)
    _require_field(commit, "subject", str, errors, prefix)
    _require_field(commit, "message_hash", str, errors, prefix)
    _require_field(commit, "diff_hash", str, errors, prefix)

    # Required integer field
    _require_field(commit, "files_changed", int, errors, prefix)

    # Required sub-objects
    _require_field(commit, "author", dict, errors, prefix)
    _require_field(commit, "committer", dict, errors, prefix)

    # Pattern checks (only if field exists and is string)
    sha = commit.get("sha")
    if isinstance(sha, str) and not _RE_SHA_HEX.match(sha):
        errors.append(f"commit.sha must be 40-64 lowercase hex chars, got {sha!r}")

    msg_hash = commit.get("message_hash")
    if isinstance(msg_hash, str) and not _RE_HASH_PREFIX.match(msg_hash):
        errors.append(f"commit.message_hash must match 'sha256:' + 64 hex chars")

    diff_hash = commit.get("diff_hash")
    if isinstance(diff_hash, str) and not _RE_HASH_PREFIX.match(diff_hash):
        errors.append(f"commit.diff_hash must match 'sha256:' + 64 hex chars")

    files_changed = commit.get("files_changed")
    if isinstance(files_changed, int) and files_changed < 0:
        errors.append(f"commit.files_changed must be >= 0, got {files_changed}")

    # Author / committer identity
    author = commit.get("author")
    if isinstance(author, dict):
        _validate_git_identity(author, errors, "commit.author")
    committer = commit.get("committer")
    if isinstance(committer, dict):
        _validate_git_identity(committer, errors, "commit.committer")

    # files vs files_redacted (mutually exclusive)
    has_files = "files" in commit
    has_redacted = "files_redacted" in commit
    if has_files and has_redacted:
        errors.append("commit must have either 'files' or 'files_redacted', not both")
    if not has_files and not has_redacted:
        errors.append("commit must have either 'files' or 'files_redacted'")

    if has_files:
        files = commit["files"]
        if not isinstance(files, list):
            errors.append(f"commit.files must be an array, got {type(files).__name__}")
        elif len(files) > 100:
            errors.append(f"commit.files must have at most 100 entries, got {len(files)}")
        else:
            for i, f in enumerate(files):
                if not isinstance(f, str):
                    errors.append(f"commit.files[{i}] must be a string")
                    break  # Don't flood errors

    if has_redacted:
        if commit["files_redacted"] is not True:
            errors.append("commit.files_redacted must be true")

    if commit.get("files_capped") is not None and commit["files_capped"] is not True:
        errors.append("commit.files_capped must be true when present")


def _validate_git_identity(
    identity: Dict[str, Any], errors: List[str], prefix: str
) -> None:
    """Validate a GitIdentity sub-object."""
    _require_field(identity, "name", str, errors, prefix)
    _require_field(identity, "email", str, errors, prefix)
    _require_field(identity, "date", str, errors, prefix)


def _validate_ai_attestation(ai: Dict[str, Any], errors: List[str]) -> None:
    """Validate the ai_attestation sub-object."""
    prefix = "ai_attestation"

    _require_field(ai, "is_ai_authored", bool, errors, prefix)
    _require_field(ai, "signals_detected", list, errors, prefix)
    _require_field(ai, "signal_count", int, errors, prefix)
    _require_field(ai, "detection_method", str, errors, prefix)

    # signal_count must match len(signals_detected)
    signals = ai.get("signals_detected")
    sig_count = ai.get("signal_count")
    if isinstance(signals, list) and isinstance(sig_count, int):
        if sig_count != len(signals):
            errors.append(
                f"ai_attestation.signal_count ({sig_count}) != "
                f"len(signals_detected) ({len(signals)})"
            )

    # All signals must be strings
    if isinstance(signals, list):
        for i, s in enumerate(signals):
            if not isinstance(s, str):
                errors.append(f"ai_attestation.signals_detected[{i}] must be a string")
                break

    # Optional bot fields — validate types when present
    if "is_bot_authored" in ai:
        if not isinstance(ai["is_bot_authored"], bool):
            errors.append(f"{prefix}.is_bot_authored must be a boolean")

    if "bot_signals_detected" in ai:
        bsigs = ai["bot_signals_detected"]
        if not isinstance(bsigs, list):
            errors.append(f"{prefix}.bot_signals_detected must be an array")
        else:
            for i, s in enumerate(bsigs):
                if not isinstance(s, str):
                    errors.append(f"{prefix}.bot_signals_detected[{i}] must be a string")
                    break

    if "bot_signal_count" in ai:
        bsc = ai["bot_signal_count"]
        if not isinstance(bsc, int):
            errors.append(f"{prefix}.bot_signal_count must be an integer")
        elif "bot_signals_detected" in ai and isinstance(ai["bot_signals_detected"], list):
            if bsc != len(ai["bot_signals_detected"]):
                errors.append(
                    f"{prefix}.bot_signal_count ({bsc}) != "
                    f"len(bot_signals_detected) ({len(ai['bot_signals_detected'])})"
                )

    if "authorship_class" in ai:
        ac = ai["authorship_class"]
        valid_classes = {"human", "ai_assisted", "ai_generated", "bot"}
        if not isinstance(ac, str) or ac not in valid_classes:
            errors.append(
                f"{prefix}.authorship_class must be one of {sorted(valid_classes)}, got {ac!r}"
            )


def _validate_provenance(prov: Dict[str, Any], errors: List[str]) -> None:
    """Validate the provenance sub-object."""
    prefix = "provenance"

    # repository can be string or null
    if "repository" not in prov:
        errors.append(f"{prefix}.repository is required")
    else:
        repo = prov["repository"]
        if repo is not None and not isinstance(repo, str):
            errors.append(f"{prefix}.repository must be a string or null")

    _require_field(prov, "tool", str, errors, prefix)
    _require_field(prov, "generator", str, errors, prefix)

    tool = prov.get("tool")
    if isinstance(tool, str) and not _RE_TOOL_URI.match(tool):
        errors.append(
            f"{prefix}.tool must start with "
            f"'https://github.com/invariant-systems-ai/aiir@', got {tool!r}"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_field(
    obj: Dict[str, Any],
    key: str,
    expected_type: type,
    errors: List[str],
    prefix: Optional[str] = None,
) -> None:
    """Check that *key* exists in *obj* and has the expected type."""
    path = f"{prefix}.{key}" if prefix else key
    if key not in obj:
        errors.append(f"{path} is required")
        return
    val = obj[key]
    # Special case: bool is a subclass of int in Python.
    # We need to distinguish bool from int explicitly.
    if expected_type is int and isinstance(val, bool):
        errors.append(f"{path} must be {expected_type.__name__}, got bool")
        return
    if expected_type is bool and isinstance(val, int) and not isinstance(val, bool):
        errors.append(f"{path} must be bool, got int")
        return
    if not isinstance(val, expected_type):
        errors.append(
            f"{path} must be {expected_type.__name__}, "
            f"got {type(val).__name__}"
        )
