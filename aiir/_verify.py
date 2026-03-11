"""
AIIR internal — receipt verification.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hmac
import json
import re
from pathlib import Path
from typing import Any, Dict

from aiir._core import (
    MAX_RECEIPT_FILE_SIZE,
    MAX_RECEIPTS_PER_RANGE,
    _canonical_json,
    _sha256,
)
from aiir._schema import validate_receipt_schema
from aiir._verify_cbor import verify_cbor_file


def verify_receipt(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Verify a receipt's content-addressed integrity.

    Recomputes content_hash and receipt_id from the receipt core and checks
    they match the stored values. Returns a dict with verification results.
    """
    # Guard against non-dict input (e.g., null entries in a receipt array).
    if not isinstance(receipt, dict):
        return {"valid": False, "errors": ["receipt is not a dict"]}

    # Validate receipt type and schema before proceeding.
    # A receipt from a different tool or an unknown schema version should
    # not silently pass verification — it could be misattributed to AIIR.
    errors = []
    rtype = receipt.get("type")
    if rtype != "aiir.commit_receipt":
        errors.append(f"unknown receipt type: {rtype!r}")
    schema = receipt.get("schema", "")
    if not isinstance(schema, str) or not schema.startswith("aiir/"):
        errors.append(f"unknown schema: {schema!r}")
    # Validate version field — reject non-string or strings with
    # HTML/control chars that could be rendered unsafely in downstream contexts.
    version = receipt.get("version")
    if not isinstance(version, str) or not re.match(
        r"^[0-9]+\.[0-9]+\.[0-9]+([.+\-][0-9a-zA-Z.+\-]*)?$", version
    ):
        errors.append(f"invalid version format: {version!r}")
    if errors:
        return {"valid": False, "errors": errors}

    # Use explicit allowlist (not denylist) for forward-compatibility.
    # New derived fields in future versions won't accidentally enter the core.
    CORE_KEYS = {"type", "schema", "version", "commit", "ai_attestation", "provenance"}
    receipt_core = {k: v for k, v in receipt.items() if k in CORE_KEYS}

    # Guard against deeply nested JSON that would blow the call stack.
    # _canonical_json now raises ValueError for depth > 64.
    try:
        core_json = _canonical_json(receipt_core)
    except (RecursionError, ValueError):
        return {"valid": False, "errors": ["receipt structure too deeply nested"]}
    expected_hash = "sha256:" + _sha256(core_json)
    expected_id = f"g1-{_sha256(core_json)[:32]}"

    stored_hash = receipt.get("content_hash", "")
    stored_id = receipt.get("receipt_id", "")

    # Constant-time comparison to prevent timing side-channel attacks.
    # hmac.compare_digest requires ASCII strings or bytes — encode to bytes
    # to safely handle any input (non-ASCII stored values are always invalid).
    try:
        hash_ok = hmac.compare_digest(
            stored_hash.encode("utf-8"), expected_hash.encode("utf-8")
        )
        id_ok = hmac.compare_digest(
            stored_id.encode("utf-8"), expected_id.encode("utf-8")
        )
    except (AttributeError, UnicodeDecodeError):  # pragma: no cover
        hash_ok = False
        id_ok = False

    valid = hash_ok and id_ok
    _commit_field = receipt.get("commit")
    result: Dict[str, Any] = {
        "valid": valid,
        "receipt_id": stored_id,
        "content_hash_match": hash_ok,
        "receipt_id_match": id_ok,
        "commit_sha": _commit_field.get("sha", "unknown")
        if isinstance(_commit_field, dict)
        else "unknown",
        "errors": [],
    }
    if not hash_ok:
        result["errors"].append("content hash mismatch")
    if not id_ok:
        result["errors"].append("receipt_id mismatch")
    # Schema validation — structural check independent of hash integrity.
    # Reported as supplementary info; does NOT override hash verdict.
    schema_errors = validate_receipt_schema(receipt)
    if schema_errors:
        result["schema_errors"] = schema_errors

    # Only expose expected hashes on valid receipts — on failure they
    # would be a forgery oracle.
    if valid:
        result["expected_content_hash"] = expected_hash
        result["expected_receipt_id"] = expected_id
    return result


def verify_receipt_file(filepath: str) -> Dict[str, Any]:
    """Load and verify a receipt JSON file.

    Note: unlike the MCP server's _safe_verify_path, the CLI does NOT
    restrict --verify to the current working directory.  This is intentional:
    --verify is read-only and the user explicitly supplies the path.
    The MCP restriction exists because an AI assistant could be tricked
    into using verify as a filesystem oracle (F4-02).
    """
    path = Path(filepath)
    if not path.exists():
        return {"valid": False, "error": f"File not found: {filepath}"}
    # Reject symlinks to prevent probing arbitrary files
    if path.is_symlink():
        return {
            "valid": False,
            "error": f"Receipt file is a symlink (refusing to verify): {filepath}",
        }
    # Reject oversized files to prevent memory exhaustion
    try:
        file_size = path.stat().st_size
    except OSError as e:  # pragma: no cover
        return {"valid": False, "error": f"Cannot stat file: {e}"}
    if file_size > MAX_RECEIPT_FILE_SIZE:
        return {
            "valid": False,
            "error": f"File too large ({file_size} bytes, max {MAX_RECEIPT_FILE_SIZE})",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return {"valid": False, "error": f"Invalid JSON: {e}"}

    # Handle single receipt or array of receipts
    if isinstance(data, list):
        # Cap array size to prevent quadratic verification DoS
        if len(data) > MAX_RECEIPTS_PER_RANGE:
            return {
                "valid": False,
                "error": f"Receipt array too large ({len(data)} items, max {MAX_RECEIPTS_PER_RANGE})",
            }
        results = [verify_receipt(r) for r in data]
        all_valid = all(r["valid"] for r in results)
        return {"valid": all_valid, "receipts": results, "count": len(results)}
    elif isinstance(data, dict):
        result = verify_receipt(data)
        # Cross-verify CBOR sidecar if it exists alongside the JSON receipt
        cbor_path = path.with_suffix(".cbor")
        if cbor_path.exists() and not cbor_path.is_symlink():
            cbor_result = verify_cbor_file(str(cbor_path), json_receipt=data)
            result["cbor_sidecar"] = cbor_result
            if not cbor_result["valid"]:
                result.setdefault("errors", []).append(
                    "CBOR sidecar verification failed"
                )
        return result
    else:  # pragma: no cover
        return {"valid": False, "error": "Expected JSON object or array"}
