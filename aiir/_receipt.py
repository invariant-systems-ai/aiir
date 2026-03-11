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
    _canonical_json,
    _now_rfc3339,
    _run_git,
    _sha256,
    _strip_terminal_escapes,
    _strip_url_credentials,
    _validate_ref,
)
from aiir._canonical_cbor import build_canonical_object_envelope, canonical_cbor_bytes
from aiir._detect import (
    get_commit_info,
    list_commits_in_range,
)


# ---------------------------------------------------------------------------
# Review receipt schema version
# ---------------------------------------------------------------------------

REVIEW_RECEIPT_SCHEMA_VERSION = "aiir/review_receipt.v1"
AIIR_CORE_KEYS = frozenset(
    {
        "type",
        "schema",
        "version",
        "commit",
        "ai_attestation",
        "provenance",
        "reviewed_commit",
        "reviewer",
        "review_outcome",
        "comment",
    }
)


# ---------------------------------------------------------------------------
# Agent attestation helpers
# ---------------------------------------------------------------------------

# Allowed keys in agent_attestation — prevents arbitrary data injection.
_AGENT_ATTESTATION_KEYS = frozenset(
    {
        "tool_id",  # e.g. "copilot", "cursor", "claude-code"
        "model_class",  # e.g. "gpt-4o", "claude-sonnet-4-20250514", "gemini-2.5-pro"
        "session_id",  # opaque session identifier
        "run_context",  # e.g. "ide", "cli", "ci", "mcp"
        "tool_version",  # e.g. "1.2.3"
        "confidence",  # e.g. "declared", "inferred", "verified"
    }
)


def _sanitize_agent_attestation(
    attestation: Optional[Dict[str, Any]],
) -> Dict[str, str]:
    """Sanitize and validate agent attestation fields.

    Only allows known keys with string values, capped at safe lengths.
    Returns a clean dict.
    """
    if not isinstance(attestation, dict):
        return {}
    clean: Dict[str, str] = {}
    for key in _AGENT_ATTESTATION_KEYS:
        val = attestation.get(key)
        if val is not None:
            # Coerce to string, strip terminal escapes, cap length
            s = _strip_terminal_escapes(str(val))[:200]
            if s:
                clean[key] = s
    return clean


def build_commit_receipt(
    commit: CommitInfo,
    repo_root: Optional[str] = None,
    redact_files: bool = False,
    instance_id: Optional[str] = None,
    namespace: Optional[str] = None,
    agent_attestation: Optional[Dict[str, Any]] = None,
    generator: str = "aiir.cli",
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
        repo_url = (
            _run_git(["remote", "get-url", "origin"], cwd=repo_root).strip() or None
        )
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
            # DAG binding — tree SHA captures directory state, parent SHAs
            # capture graph position.  Together they make receipt laundering
            # (reusing a receipt across commits) structurally impossible.
            "tree_sha": commit.tree_sha,
            "parent_shas": commit.parent_shas,
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
            **(
                {"files": commit.files_changed[:100]}
                if not redact_files
                else {"files_redacted": True}  # type: ignore[dict-item]
            ),
            # Indicate when file list was truncated so verifiers know
            # the full list is not present.
            **(
                {"files_capped": True}
                if not redact_files and len(commit.files_changed) > 100
                else {}
            ),
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
            "generator": generator,
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
            **(
                ({"agent_attestation": _sanitize_agent_attestation(agent_attestation)})
                if agent_attestation
                else {}
            ),
        },
    }

    return receipt


def build_review_receipt(
    reviewed_commit: str,
    reviewer_name: str,
    reviewer_email: str,
    review_outcome: str = "approved",
    commit_receipt_id: Optional[str] = None,
    comment: Optional[str] = None,
    cwd: Optional[str] = None,
    instance_id: Optional[str] = None,
    namespace: Optional[str] = None,
    agent_attestation: Optional[Dict[str, Any]] = None,
    generator: str = "aiir.cli",
) -> Dict[str, Any]:
    """Build a review receipt attesting that a human reviewed a commit.

    The receipt is content-addressed, following the same pattern as
    :func:`build_commit_receipt`.

    Args:
        reviewed_commit: The commit SHA that was reviewed.
        reviewer_name: Name of the reviewer.
        reviewer_email: Email of the reviewer.
        review_outcome: One of ``approved``, ``rejected``, ``commented``.
        commit_receipt_id: Optional receipt_id of the corresponding commit receipt.
        comment: Optional review comment.
        cwd: Repository root (for provenance).
        instance_id: Optional instance identifier.
        namespace: Optional namespace.
        agent_attestation: Optional agent attestation dict (tool_id, model_class, etc.).
        generator: Generator identifier.

    Returns:
        A content-addressed review receipt dict.
    """
    _VALID_OUTCOMES = ("approved", "rejected", "commented")
    if review_outcome not in _VALID_OUTCOMES:
        raise ValueError(
            f"Invalid review_outcome: {review_outcome!r}. "
            f"Must be one of: {', '.join(_VALID_OUTCOMES)}"
        )

    _validate_ref(reviewed_commit)
    now = _now_rfc3339()

    # Determine repo identity
    repo_url: Optional[str] = None
    try:
        repo_url = _run_git(["remote", "get-url", "origin"], cwd=cwd).strip() or None
        if repo_url:
            repo_url = _strip_url_credentials(repo_url)
    except RuntimeError:
        pass

    # Sanitize inputs
    reviewer_name = _strip_terminal_escapes(str(reviewer_name))[:200]
    reviewer_email = _strip_terminal_escapes(str(reviewer_email))[:200]
    comment_safe = _strip_terminal_escapes(str(comment))[:2000] if comment else None

    receipt_core: Dict[str, Any] = {
        "type": "aiir.review_receipt",
        "schema": REVIEW_RECEIPT_SCHEMA_VERSION,
        "version": CLI_VERSION,
        "reviewed_commit": {
            "sha": _strip_terminal_escapes(str(reviewed_commit))[:64],
            **(
                {"receipt_id": _strip_terminal_escapes(str(commit_receipt_id))[:40]}
                if commit_receipt_id
                else {}
            ),
        },
        "reviewer": {
            "name": reviewer_name,
            "email": reviewer_email,
        },
        "review_outcome": review_outcome,
        **({"comment": comment_safe} if comment_safe else {}),
        "provenance": {
            "repository": repo_url,
            "tool": f"https://github.com/invariant-systems-ai/aiir@{CLI_VERSION}",
            "generator": generator,
        },
    }

    core_json = _canonical_json(receipt_core)
    content_hash = "sha256:" + _sha256(core_json)
    receipt_id = f"g1-{_sha256(core_json)[:32]}"

    receipt: Dict[str, Any] = {
        **receipt_core,
        "receipt_id": receipt_id,
        "content_hash": content_hash,
        "timestamp": now,
        "extensions": {
            **(({"instance_id": instance_id}) if instance_id else {}),
            **(({"namespace": namespace}) if namespace else {}),
            **(
                ({"agent_attestation": _sanitize_agent_attestation(agent_attestation)})
                if agent_attestation
                else {}
            ),
        },
    }

    return receipt


def _extract_receipt_core(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the stable, identity-bearing core from a receipt."""

    return {k: receipt[k] for k in AIIR_CORE_KEYS if k in receipt}


def _canonical_object_kind(receipt: Dict[str, Any]) -> str:
    rtype = str(receipt.get("type") or "aiir.receipt")
    return f"{rtype}.core"


def _canonical_receipt_cbor_bytes(receipt: Dict[str, Any]) -> bytes:
    """Build the Layer-0 canonical CBOR envelope for a receipt core."""

    core = _extract_receipt_core(receipt)
    envelope = build_canonical_object_envelope(
        kind=_canonical_object_kind(receipt),
        object_schema=str(receipt.get("schema") or RECEIPT_SCHEMA_VERSION),
        core=core,
    )
    return canonical_cbor_bytes(envelope)


def _write_bytes_atomic(path: Path, data: bytes) -> None:
    """Write bytes atomically with fixed permissions."""

    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    if _HAS_FCHMOD:
        os.fchmod(fd, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def generate_receipt(
    commit_ref: str = "HEAD",
    cwd: Optional[str] = None,
    ai_only: bool = False,
    redact_files: bool = False,
    instance_id: Optional[str] = None,
    namespace: Optional[str] = None,
    agent_attestation: Optional[Dict[str, Any]] = None,
    generator: str = "aiir.cli",
) -> Optional[Dict[str, Any]]:
    """Generate a receipt for a single commit. Returns None if skipped."""
    _validate_ref(commit_ref)
    commit = get_commit_info(commit_ref, cwd=cwd)

    if ai_only and not commit.is_ai_authored:
        return None

    return build_commit_receipt(
        commit,
        repo_root=cwd,
        redact_files=redact_files,
        instance_id=instance_id,
        namespace=namespace,
        agent_attestation=agent_attestation,
        generator=generator,
    )


def generate_receipts_for_range(
    range_spec: str,
    cwd: Optional[str] = None,
    ai_only: bool = False,
    redact_files: bool = False,
    instance_id: Optional[str] = None,
    namespace: Optional[str] = None,
    agent_attestation: Optional[Dict[str, Any]] = None,
    generator: str = "aiir.cli",
) -> List[Dict[str, Any]]:
    """Generate receipts for all commits in a range."""
    shas = list_commits_in_range(range_spec, cwd=cwd)
    receipts = []
    for sha in shas:
        receipt = generate_receipt(
            sha,
            cwd=cwd,
            ai_only=ai_only,
            redact_files=redact_files,
            instance_id=instance_id,
            namespace=namespace,
            agent_attestation=agent_attestation,
            generator=generator,
        )
        if receipt is not None:
            receipts.append(receipt)
    return receipts


# ---------------------------------------------------------------------------
# in-toto Statement v1 envelope
# ---------------------------------------------------------------------------

# Predicate type URI registered for AIIR commit receipts.
# Format: https://in-toto.io/attestation/v1#predicateType
INTOTO_PREDICATE_TYPE = "https://invariantsystems.io/predicates/aiir/commit_receipt/v1"


def wrap_in_toto_statement(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Wrap an AIIR receipt in an in-toto Statement v1 envelope.

    The in-toto attestation framework (https://in-toto.io) defines a
    standard envelope for software supply-chain attestations.  This function
    wraps a single AIIR commit receipt so that it can be consumed by any
    tool that understands in-toto — Sigstore policy-controller, SLSA
    verifiers, Kyverno, OPA/Gatekeeper, Tekton Chains, etc.

    Envelope shape (https://in-toto.io/Statement/v1):

        {
          "_type": "https://in-toto.io/Statement/v1",
          "subject": [
            {
              "name": "<repository>@<commit_sha>",
              "digest": { "gitCommit": "<full_sha>" }
            }
          ],
          "predicateType": "https://invariantsystems.io/predicates/aiir/commit_receipt/v1",
          "predicate": { <the receipt> }
        }

    The `subject` identifies the git commit; the `predicate` is the
    full AIIR receipt including its content hash.  Downstream verifiers
    can match on `predicateType` to route attestations.

    Returns:
        A dict conforming to the in-toto Statement v1 schema.
    """
    commit = receipt.get("commit", {})
    if not isinstance(commit, dict):
        commit = {}

    sha = commit.get("sha", "")
    repo = receipt.get("provenance", {})
    if not isinstance(repo, dict):
        repo = {}
    repo_url = repo.get("repository") or "unknown"

    # Subject name: <repo>@<sha> (mirrors OCI artifact naming)
    subject_name = f"{_strip_url_credentials(repo_url)}@{sha}" if sha else repo_url

    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": _strip_terminal_escapes(subject_name),
                "digest": {"gitCommit": _strip_terminal_escapes(str(sha))},
            }
        ],
        "predicateType": INTOTO_PREDICATE_TYPE,
        "predicate": receipt,
    }


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def format_receipt_pretty(receipt: Dict[str, Any], signed: str = "none") -> str:
    """Human-readable receipt summary.

    Args:
        receipt: The receipt dict.
        signed: Signing status to display (e.g. 'YES (sigstore)' or 'none').
    """
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
    subject = _strip_terminal_escapes(commit.get("subject", ""))
    # Guard author sub-field type — extends defensive pattern to
    # nested fields.  A crafted receipt with author as string/int/list/None
    # would crash the .get('name', '') call with AttributeError.
    author = commit.get("author", {})
    if not isinstance(author, dict):
        author = {}
    author_name = _strip_terminal_escapes(author.get("name", ""))
    author_email = _strip_terminal_escapes(author.get("email", ""))
    receipt_id = _strip_terminal_escapes(str(receipt.get("receipt_id", "unknown")))
    commit_sha = _strip_terminal_escapes(str(commit.get("sha", "unknown"))[:12])
    content_hash = _strip_terminal_escapes(str(receipt.get("content_hash", "")))
    timestamp = _strip_terminal_escapes(str(receipt.get("timestamp", "")))
    # Coerce files_changed to int — a crafted receipt could
    # inject arbitrary strings via this field into terminal output.
    # Also catch OverflowError — int(float('inf')) raises
    # OverflowError, and json.loads('1e999') produces float('inf').
    try:
        files_count = int(commit.get("files_changed", 0))
    except (TypeError, ValueError, OverflowError):
        files_count = 0
    # Guard against non-list signals_detected — a crafted
    # receipt with signals_detected as a dict or string would crash on
    # slicing (dict[:3] raises TypeError).  Coerce to empty list.
    signals = ai.get("signals_detected", [])
    if not isinstance(signals, (list, tuple)):
        signals = []
    # Box-drawing chars → _b() for encoding safety.
    # Lazy-import cli._b so that tests toggling cli._USE_BOXDRAW are respected.
    from aiir.cli import _b as _box  # noqa: PLC0415 — lazy to avoid circular import

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
        f"{vl}  Signed:  {_strip_terminal_escapes(signed)}",
        f"{bl}{hl * 42}",
    ]
    return "\n".join(lines)


def format_receipt_detail(receipt: Dict[str, Any], signed: str = "none") -> str:
    """Detailed human-readable receipt — shows all fields.

    Same box-drawing style as format_receipt_pretty, but includes every
    field from the receipt JSON: schema identity, committer, hashes,
    file list, full AI attestation, provenance, and extensions.

    Args:
        receipt: The receipt dict.
        signed: Signing status to display (e.g. 'YES (sigstore)' or 'none').
    """
    # ── Safe extraction (same defensive pattern as format_receipt_pretty) ──
    commit = receipt.get("commit", {})
    ai = receipt.get("ai_attestation", {})
    provenance = receipt.get("provenance", {})
    extensions = receipt.get("extensions", {})
    if not isinstance(commit, dict):
        commit = {}
    if not isinstance(ai, dict):
        ai = {}
    if not isinstance(provenance, dict):
        provenance = {}
    if not isinstance(extensions, dict):
        extensions = {}

    def _safe(obj: Any, key: str, default: str = "") -> str:
        return _strip_terminal_escapes(str(obj.get(key, default)))

    def _safe_dict(obj: Any, key: str) -> dict:
        val = obj.get(key, {}) if isinstance(obj, dict) else {}
        return val if isinstance(val, dict) else {}

    author = _safe_dict(commit, "author")
    committer = _safe_dict(commit, "committer")

    # Guard files list — must be a list of strings.
    files = commit.get("files", [])
    if not isinstance(files, (list, tuple)):
        files = []

    # Guard signals — same pattern as pretty.
    signals = ai.get("signals_detected", [])
    if not isinstance(signals, (list, tuple)):
        signals = []
    bot_signals = ai.get("bot_signals_detected", [])
    if not isinstance(bot_signals, (list, tuple)):
        bot_signals = []

    try:
        files_count = int(commit.get("files_changed", 0))
    except (TypeError, ValueError, OverflowError):
        files_count = 0

    # Box-drawing chars
    from aiir.cli import _b as _box  # noqa: PLC0415

    tl, vl, bl_char, hl = _box("tl"), _box("vl"), _box("bl"), _box("hl")
    sec = f"{vl}{'─' * 44}"  # section separator

    lines = [
        f"{tl}{hl} Receipt: {_safe(receipt, 'receipt_id', 'unknown')}",
        sec,
        f"{vl}  Type:    {_safe(receipt, 'type')}",
        f"{vl}  Schema:  {_safe(receipt, 'schema')}",
        f"{vl}  Version: {_safe(receipt, 'version')}",
        sec,
        f"{vl}  Commit:     {_safe(commit, 'sha', 'unknown')}",
        f"{vl}  Subject:    {_safe(commit, 'subject')}",
        f"{vl}  Author:     {_safe(author, 'name')} <{_safe(author, 'email')}>",
        f"{vl}               {_safe(author, 'date')}",
        f"{vl}  Committer:  {_safe(committer, 'name')} <{_safe(committer, 'email')}>",
        f"{vl}               {_safe(committer, 'date')}",
        f"{vl}  Msg hash:   {_safe(commit, 'message_hash')}",
        f"{vl}  Diff hash:  {_safe(commit, 'diff_hash')}",
        f"{vl}  Files:      {files_count} changed",
    ]

    # File list — cap at 20 to prevent terminal flooding from crafted receipts.
    for f in files[:20]:
        if isinstance(f, str):
            lines.append(f"{vl}               {_strip_terminal_escapes(f)[:120]}")
    if len(files) > 20:
        lines.append(f"{vl}               ... and {len(files) - 20} more")

    lines.append(sec)
    lines.append(f"{vl}  AI:           {'YES' if ai.get('is_ai_authored') else 'no'}")
    lines.append(f"{vl}  Class:        {_safe(ai, 'authorship_class', 'unknown')}")
    lines.append(f"{vl}  Method:       {_safe(ai, 'detection_method', 'unknown')}")

    # Signals
    if signals:
        sig_str = ", ".join(
            _strip_terminal_escapes(str(s))[:80]
            for s in signals[:10]
            if isinstance(s, (str, int, float))
        )
        lines.append(f"{vl}  Signals:      {sig_str}")
    else:
        lines.append(f"{vl}  Signals:      none")

    try:
        sig_count = int(ai.get("signal_count", 0))
    except (TypeError, ValueError, OverflowError):
        sig_count = 0
    lines.append(f"{vl}  Signal count: {sig_count}")

    # Bot attestation
    lines.append(f"{vl}  Bot:          {'YES' if ai.get('is_bot_authored') else 'no'}")
    if bot_signals:
        bot_str = ", ".join(
            _strip_terminal_escapes(str(s))[:80]
            for s in bot_signals[:10]
            if isinstance(s, (str, int, float))
        )
        lines.append(f"{vl}  Bot signals:  {bot_str}")

    lines.append(sec)
    lines.append(f"{vl}  Repo:     {_safe(provenance, 'repository')}")
    lines.append(f"{vl}  Tool:     {_safe(provenance, 'tool')}")
    lines.append(
        f"{vl}  Generator:{' ' if _safe(provenance, 'generator') else ''}{_safe(provenance, 'generator')}"
    )

    lines.append(sec)
    lines.append(f"{vl}  Hash:    {_safe(receipt, 'content_hash')}")
    lines.append(f"{vl}  Time:    {_safe(receipt, 'timestamp')}")
    lines.append(f"{vl}  Signed:  {_strip_terminal_escapes(signed)}")

    # Extensions — show keys and short values if present.
    if extensions:
        lines.append(sec)
        for i, (k, v) in enumerate(extensions.items()):
            if i >= 10:
                lines.append(f"{vl}  ... and {len(extensions) - 10} more")
                break
            k_safe = _strip_terminal_escapes(str(k))[:40]
            v_safe = _strip_terminal_escapes(str(v))[:80]
            lines.append(f"{vl}  ext.{k_safe}: {v_safe}")

    lines.append(f"{bl_char}{hl * 46}")
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
        except ValueError as exc:
            raise ValueError(
                f"output-dir must be within the working directory: {output_dir!r} "
                f"resolves outside {cwd_resolved}"
            ) from exc
        out_path.mkdir(parents=True, exist_ok=True)
        # Re-verify after mkdir to narrow TOCTOU/symlink race window
        real_out = out_path.resolve()
        try:
            real_out.relative_to(cwd_resolved)
        except ValueError as exc:  # pragma: no cover — TOCTOU race
            raise ValueError(
                "output-dir escaped working directory after creation "
                "(possible symlink attack)"
            ) from exc
        commit_sha = receipt.get("commit", {}).get("sha", "unknown")[:12]
        commit_sha = re.sub(r"[^a-zA-Z0-9_-]", "_", commit_sha)
        # Deterministic filename from content_hash — makes it easy to
        # check if a receipt already exists for a given commit.
        chash = receipt.get("content_hash", "")
        chash_short = re.sub(r"[^a-fA-F0-9]", "", chash)[:16]
        filename = f"receipt_{commit_sha}_{chash_short}.json"
        filepath = out_path / filename
        cbor_path = filepath.with_suffix(".cbor")
        # If this exact receipt already exists, return existing path
        if filepath.exists():
            if not cbor_path.exists():
                _write_bytes_atomic(cbor_path, _canonical_receipt_cbor_bytes(receipt))
            return str(filepath)
        fd = os.open(str(filepath), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        # os.open mode is masked by umask — force 0o600 after creation
        if _HAS_FCHMOD:
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(receipt_json + "\n")
        _write_bytes_atomic(cbor_path, _canonical_receipt_cbor_bytes(receipt))
        return str(filepath)
    elif jsonl:
        # JSON Lines: one receipt per line, no pretty printing
        print(_canonical_json(receipt), flush=True)
        return "stdout:jsonl"
    else:
        print(receipt_json, flush=True)
        return "stdout:json"
