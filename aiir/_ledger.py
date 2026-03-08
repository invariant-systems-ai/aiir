"""
AIIR internal — append-only JSONL receipt ledger with auto-index.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aiir._core import (
    CONFIG_FILE,
    INDEX_FILE,
    LEDGER_DIR,
    LEDGER_FILE,
    _HAS_FCHMOD,
    _canonical_json,
    _now_rfc3339,
)


def _ledger_paths(
    ledger_dir: Optional[str] = None,
) -> Tuple[Path, Path, Path]:
    """Return (dir, ledger_path, index_path) for the ledger."""
    base = Path(ledger_dir or LEDGER_DIR).resolve()
    return base, base / LEDGER_FILE, base / INDEX_FILE


def _config_path(config_dir: Optional[str] = None) -> Path:
    """Return the path to the config file."""
    return Path(config_dir or LEDGER_DIR).resolve() / CONFIG_FILE


def _load_config(config_dir: Optional[str] = None) -> Dict[str, Any]:
    """Load .aiir/config.json, creating it with a fresh instance_id if absent."""
    dir_path = Path(config_dir or LEDGER_DIR).resolve()
    cfg_path = dir_path / CONFIG_FILE
    if cfg_path.is_file():
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("instance_id"), str):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    # Generate a new config with a stable instance_id.
    config: Dict[str, Any] = {
        "instance_id": str(uuid.uuid4()),
        "created": _now_rfc3339(),
    }
    dir_path.mkdir(parents=True, exist_ok=True)
    _save_config(cfg_path, config)
    return config


def _save_config(cfg_path: Path, config: Dict[str, Any]) -> None:
    """Atomically write the config file."""
    tmp = cfg_path.with_suffix(".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    if _HAS_FCHMOD:
        os.fchmod(fd, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(str(tmp), str(cfg_path))


def _load_index(index_path: Path) -> Dict[str, Any]:
    """Load the ledger index, or return a fresh skeleton."""
    if index_path.is_file():
        try:
            data = json.loads(index_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("version") == 1:
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return {
        "version": 1,
        "receipt_count": 0,
        "ai_commit_count": 0,
        "ai_percentage": 0.0,
        "first_receipt": None,
        "latest_timestamp": None,
        "unique_authors": 0,
        "commits": {},
    }


def _save_index(index_path: Path, index: Dict[str, Any]) -> None:
    """Atomically write the ledger index."""
    tmp = index_path.with_suffix(".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    if _HAS_FCHMOD:
        os.fchmod(fd, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(str(tmp), str(index_path))


def append_to_ledger(
    receipts: List[Dict[str, Any]],
    ledger_dir: Optional[str] = None,
) -> Tuple[int, int, str]:
    """Append receipts to the JSONL ledger, skipping duplicates.

    Returns (appended_count, skipped_count, ledger_path_str).
    """
    dir_path, ledger_path, index_path = _ledger_paths(ledger_dir)

    # Path-traversal guard — same logic as write_receipt.
    cwd_resolved = Path(os.getcwd()).resolve()
    try:
        dir_path.relative_to(cwd_resolved)
    except ValueError:
        raise ValueError(
            f"ledger dir must be within the working directory: "
            f"{dir_path} resolves outside {cwd_resolved}"
        )
    dir_path.mkdir(parents=True, exist_ok=True)
    # Re-verify after mkdir (symlink TOCTOU defence).
    real_dir = dir_path.resolve()
    try:
        real_dir.relative_to(cwd_resolved)
    except ValueError:
        raise ValueError(
            "ledger dir escaped working directory after creation "
            "(possible symlink attack)"
        )

    index = _load_index(index_path)
    known_commits: Dict[str, Any] = index.get("commits", {})

    appended = 0
    skipped = 0

    # Append new receipts — open once, write all, then flush.
    fd = os.open(
        str(ledger_path),
        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
        0o644,
    )
    if _HAS_FCHMOD:
        os.fchmod(fd, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        for receipt in receipts:
            sha = receipt.get("commit", {}).get("sha", "")
            if not sha:
                continue

            # Dedup: skip if this commit SHA is already in the index.
            if sha in known_commits:
                skipped += 1
                continue

            line = _canonical_json(receipt)
            f.write(line + "\n")
            appended += 1

            is_ai = receipt.get("ai_attestation", {}).get("is_ai_authored", False)
            rid = receipt.get("receipt_id", "")
            ts = receipt.get("timestamp", "")

            author_email = receipt.get("commit", {}).get("author", {}).get("email", "")
            known_commits[sha] = {
                "receipt_id": rid,
                "ai": is_ai,
                "author": author_email,
                "line": index.get("receipt_count", 0) + appended,
            }
            if is_ai:
                index["ai_commit_count"] = index.get("ai_commit_count", 0) + 1
            if index.get("first_receipt") is None:
                index["first_receipt"] = ts
            index["latest_timestamp"] = ts

    index["receipt_count"] = index.get("receipt_count", 0) + appended
    index["commits"] = known_commits
    # Compute derived stats.
    authors = {v.get("author", "") for v in known_commits.values() if isinstance(v, dict) and v.get("author")}
    index["unique_authors"] = len(authors)
    total = index["receipt_count"]
    index["ai_percentage"] = round(index.get("ai_commit_count", 0) / total * 100, 1) if total > 0 else 0.0
    _save_index(index_path, index)

    return appended, skipped, str(ledger_path)


def export_ledger(
    ledger_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Bundle the .aiir/ ledger into a portable JSON export.

    Returns a dict suitable for serialization.  The format is designed so
    that managed services can ingest it in a single upload.
    """
    dir_path, ledger_path, index_path = _ledger_paths(ledger_dir)

    # Load existing data.
    index = _load_index(index_path)
    config = _load_config(str(dir_path))
    receipts: List[Dict[str, Any]] = []
    if ledger_path.is_file():
        for line in ledger_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    receipts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    return {
        "format": "aiir.export.v1",
        "exported_at": _now_rfc3339(),
        "instance_id": config.get("instance_id"),
        "namespace": config.get("namespace"),
        "index": index,
        "receipts": receipts,
    }
