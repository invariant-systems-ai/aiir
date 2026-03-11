"""
AIIR Hub Sync — push receipts to Invariant Systems Hub.

Stdlib-only module (urllib.request) — no new dependencies.
AIIR is its own first Hub customer: this module enables the public
aiir CLI to push locally-generated receipts into the Hub SaaS.

Usage (CLI)::

    aiir hub status           # check connectivity
    aiir hub sync             # push all un-synced ledger receipts
    aiir hub push FILE        # push a single receipt file

Usage (Python)::

    from aiir._hub_sync import hub_status, hub_push, hub_push_from_ledger
    hub_status()
    hub_push([receipt_dict])
    hub_push_from_ledger()

Config via env:
    AIIR_HUB_URL     Hub base URL (default: https://hub.invariantsystems.io)
    AIIR_HUB_TOKEN   Bearer token for the tenant

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_DEFAULT_HUB_URL = "https://hub.invariantsystems.io"
_BATCH_SIZE = 100  # matches Hub's _MAX_BATCH_SIZE


def _hub_url() -> str:
    return os.environ.get("AIIR_HUB_URL", _DEFAULT_HUB_URL).rstrip("/")


def _hub_token() -> str:
    return os.environ.get("AIIR_HUB_TOKEN", "")


# ---------------------------------------------------------------------------
# Sync state — tracks which receipt_ids have been pushed
# ---------------------------------------------------------------------------

def _sync_state_path() -> Path:
    """Return path to .aiir/hub_sync.jsonl (sibling to the receipt ledger)."""
    return Path.cwd() / ".aiir" / "hub_sync.jsonl"


def _load_synced_ids() -> set[str]:
    """Load the set of receipt IDs already pushed to Hub."""
    path = _sync_state_path()
    if not path.exists():
        return set()
    ids: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            rid = record.get("receipt_id", "")
            if rid:
                ids.add(rid)
        except json.JSONDecodeError:
            continue
    return ids


def _mark_synced(receipt_ids: list[str]) -> None:
    """Record that these receipt IDs have been synced."""
    path = _sync_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(path, "a", encoding="utf-8") as f:
        for rid in receipt_ids:
            f.write(json.dumps({"receipt_id": rid, "synced_at": ts}, separators=(",", ":")) + "\n")


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------

def _api_request(
    method: str,
    path: str,
    body: Optional[bytes] = None,
    timeout: int = 30,
) -> dict:
    """Make an authenticated HTTP request to the Hub API.

    Returns a dict with 'status', 'body' (parsed JSON or raw str), and 'ok'.
    """
    url = _hub_url() + path
    token = _hub_token()

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    headers["User-Agent"] = "aiir-hub-sync/1.0"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = raw
            return {"status": resp.status, "body": data, "ok": True}
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read().decode("utf-8")
        except Exception:
            pass
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            data = raw
        return {"status": e.code, "body": data, "ok": False}
    except urllib.error.URLError as e:
        return {"status": 0, "body": str(e.reason), "ok": False}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def hub_status() -> dict:
    """Check connectivity and auth with Hub.

    Returns:
        dict with 'ok', 'hub_url', 'authenticated', 'detail'.
    """
    result = _api_request("GET", "/v1/health")
    authenticated = False

    if result["ok"] and _hub_token():
        # Try an authenticated endpoint to verify the token
        auth_check = _api_request("GET", "/v1/receipts/nonexistent-probe")
        # 404 means authenticated but receipt not found (good)
        # 401/403 means bad token
        if auth_check["status"] in (404, 200):
            authenticated = True

    return {
        "ok": result["ok"],
        "hub_url": _hub_url(),
        "authenticated": authenticated,
        "detail": result["body"],
    }


def hub_push(receipts: List[Dict[str, Any]]) -> dict:
    """Push a list of receipt dicts to Hub.

    Returns:
        dict with 'ok', 'total', 'verified', 'failed', 'results'.
    """
    if not _hub_token():
        return {"ok": False, "error": "AIIR_HUB_TOKEN not set", "total": 0, "verified": 0, "failed": len(receipts)}

    all_results: list[dict] = []
    total_verified = 0
    total_failed = 0

    # Push in batches
    for i in range(0, len(receipts), _BATCH_SIZE):
        batch = receipts[i : i + _BATCH_SIZE]
        body = json.dumps({"receipts": batch}, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        result = _api_request("POST", "/v1/receipts", body=body)

        if result["ok"] and isinstance(result["body"], dict):
            batch_result = result["body"]
            all_results.extend(batch_result.get("results", []))
            total_verified += batch_result.get("verified", 0)
            total_failed += batch_result.get("failed", 0)
        else:
            # Entire batch failed
            for r in batch:
                all_results.append({
                    "ok": False,
                    "receipt_id": r.get("receipt_id", ""),
                    "status": "failed",
                    "errors": [f"HTTP {result['status']}: {result['body']}"],
                })
                total_failed += 1

    return {
        "ok": total_failed == 0,
        "total": len(receipts),
        "verified": total_verified,
        "failed": total_failed,
        "results": all_results,
    }


def hub_push_from_ledger() -> dict:
    """Push all un-synced receipts from the local ledger to Hub.

    Reads .aiir/receipts.jsonl, compares against .aiir/hub_sync.jsonl,
    and pushes any new receipts.

    Returns:
        dict with 'ok', 'pushed', 'skipped', 'errors'.
    """
    ledger_path = Path.cwd() / ".aiir" / "receipts.jsonl"
    if not ledger_path.exists():
        return {"ok": True, "pushed": 0, "skipped": 0, "errors": [], "detail": "no ledger found"}

    # Load all receipts from ledger
    all_receipts: list[dict] = []
    for line in ledger_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            all_receipts.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if not all_receipts:
        return {"ok": True, "pushed": 0, "skipped": 0, "errors": []}

    # Filter out already-synced
    synced_ids = _load_synced_ids()
    to_push = [r for r in all_receipts if r.get("receipt_id", "") not in synced_ids]

    if not to_push:
        return {"ok": True, "pushed": 0, "skipped": len(all_receipts), "errors": []}

    # Push
    result = hub_push(to_push)

    # Record successful syncs
    pushed_ids = [
        r.get("receipt_id", "")
        for r in result.get("results", [])
        if r.get("ok")
    ]
    if pushed_ids:
        _mark_synced(pushed_ids)

    return {
        "ok": result["ok"],
        "pushed": result.get("verified", 0),
        "skipped": len(synced_ids),
        "errors": [
            r.get("errors", [])
            for r in result.get("results", [])
            if not r.get("ok")
        ],
    }


# ---------------------------------------------------------------------------
# CLI entry point (called from aiir.cli when `aiir hub ...` is invoked)
# ---------------------------------------------------------------------------

def hub_cli(args: Sequence[str]) -> int:
    """Handle `aiir hub <subcommand>`."""
    if not args or args[0] in ("-h", "--help"):
        print("usage: aiir hub {status,sync,push} [args]")
        print()
        print("subcommands:")
        print("  status     Check Hub connectivity and authentication")
        print("  sync       Push all un-synced ledger receipts to Hub")
        print("  push FILE  Push a single receipt JSON file to Hub")
        print()
        print("environment:")
        print(f"  AIIR_HUB_URL    {_hub_url()}")
        print(f"  AIIR_HUB_TOKEN  {'(set)' if _hub_token() else '(not set)'}")
        return 0

    cmd = args[0]

    if cmd == "status":
        result = hub_status()
        if result["ok"]:
            auth_status = "authenticated" if result["authenticated"] else "anonymous"
            print(f"Hub: {result['hub_url']}  ({auth_status})")
            if isinstance(result["detail"], dict):
                svc = result["detail"].get("service", "")
                ver = result["detail"].get("api_version", "")
                if svc:
                    print(f"  service: {svc} v{ver}")
        else:
            print(f"Hub: {result['hub_url']}  (unreachable)", file=sys.stderr)
            print(f"  error: {result['detail']}", file=sys.stderr)
            return 1
        return 0

    elif cmd == "sync":
        if not _hub_token():
            print("error: AIIR_HUB_TOKEN not set", file=sys.stderr)
            return 1
        result = hub_push_from_ledger()
        print(f"pushed: {result['pushed']}  skipped: {result['skipped']}")
        if result.get("errors"):
            for err in result["errors"]:
                print(f"  error: {err}", file=sys.stderr)
        return 0 if result["ok"] else 1

    elif cmd == "push":
        if len(args) < 2:
            print("usage: aiir hub push FILE [FILE ...]", file=sys.stderr)
            return 1
        if not _hub_token():
            print("error: AIIR_HUB_TOKEN not set", file=sys.stderr)
            return 1

        receipts: list[dict] = []
        for filepath in args[1:]:
            p = Path(filepath)
            if not p.is_file():
                print(f"warning: {filepath}: not found, skipping", file=sys.stderr)
                continue
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    receipts.append(data)
                elif isinstance(data, list):
                    receipts.extend(data)
            except (json.JSONDecodeError, OSError) as exc:
                print(f"warning: {filepath}: {exc}", file=sys.stderr)
                continue

        if not receipts:
            print("no valid receipts to push")
            return 0

        result = hub_push(receipts)
        print(f"total: {result['total']}  verified: {result.get('verified', 0)}  failed: {result.get('failed', 0)}")
        for r in result.get("results", []):
            status = "ok" if r.get("ok") else "FAIL"
            print(f"  [{status}] {r.get('receipt_id', '?')}")
            for e in r.get("errors", []):
                print(f"         {e}", file=sys.stderr)
        return 0 if result["ok"] else 1

    else:
        print(f"unknown subcommand: {cmd}", file=sys.stderr)
        print("usage: aiir hub {status,sync,push}", file=sys.stderr)
        return 1
