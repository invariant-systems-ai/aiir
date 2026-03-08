"""
AIIR internal — Sigstore signing and verification (optional dependency).

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

from aiir._core import (
    MAX_RECEIPT_FILE_SIZE,
    _HAS_FCHMOD,
)


def _sigstore_available() -> bool:
    """Check if the sigstore package is available for import."""
    try:
        import sigstore  # noqa: F401

        return True
    except ImportError:
        return False


def sign_receipt(receipt_json_bytes: bytes) -> str:
    """Sign receipt bytes using Sigstore keyless signing.

    Uses ambient OIDC credentials in CI (GitHub Actions, GitLab CI, etc.)
    or falls back to interactive browser-based OIDC flow for local use.

    Returns the Sigstore bundle as a JSON string.
    """
    try:
        from sigstore.models import ClientTrustConfig
        from sigstore.oidc import IdentityToken, Issuer, detect_credential
        from sigstore.sign import SigningContext
    except ImportError:
        raise RuntimeError(
            "Sigstore signing requires the 'sigstore' package.\n"
            "Install with: pip install sigstore"
        )

    # Try ambient credential first (GitHub Actions, GitLab CI, etc.)
    raw_token = detect_credential()
    if raw_token is not None:
        identity_token = IdentityToken(raw_token)
    else:
        # Detect CI environment — if we're in CI but have no ambient
        # credential, the user is missing permissions (e.g., id-token: write)
        # or this is a fork PR (which can't get OIDC tokens).
        # Give a clear error instead of hanging on interactive browser flow.
        ci_env = (
            os.environ.get("CI")
            or os.environ.get("GITHUB_ACTIONS")
            or os.environ.get("GITLAB_CI")
            or os.environ.get("BITBUCKET_BUILD_NUMBER")
            or os.environ.get("CIRCLECI")
            or os.environ.get("JENKINS_URL")
            or os.environ.get("TF_BUILD")  # Azure Pipelines
        )
        if ci_env:
            hints = []
            if os.environ.get("GITHUB_ACTIONS"):
                hints.append(
                    "  - Add 'permissions: { id-token: write }' to your workflow"
                )
                if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":  # pragma: no cover
                    hints.append(
                        "  - Fork PRs cannot obtain OIDC tokens — use 'sign: false' for fork PRs"
                    )
            elif os.environ.get("GITLAB_CI"):  # pragma: no cover
                hints.append(
                    "  - Ensure CI_JOB_JWT or SIGSTORE_ID_TOKEN is available"
                )
            hint_text = "\n".join(hints) if hints else "  - Ensure OIDC credentials are available in this CI environment"
            raise RuntimeError(
                "Sigstore signing failed: no ambient OIDC credential detected.\n"
                "This usually means the CI runner cannot obtain an identity token.\n"
                f"{hint_text}\n"
                "  - Or disable signing with --no-sign / sign: false"
            )
        # Local development — fall back to interactive OIDC flow (opens browser)
        issuer = Issuer.production()
        identity_token = issuer.identity_token()

    config = ClientTrustConfig.production()
    ctx = SigningContext.from_trust_config(config)
    with ctx.signer(identity_token) as signer:
        bundle = signer.sign_artifact(receipt_json_bytes)
    return bundle.to_json()


def sign_receipt_file(receipt_path: str) -> str:
    """Sign a receipt file and write the Sigstore bundle alongside it.

    Given 'receipt_abc.json', writes 'receipt_abc.json.sigstore'.
    Returns the bundle file path.
    """
    path = Path(receipt_path)
    if not path.exists():
        raise FileNotFoundError(f"Receipt file not found: {receipt_path}")

    # Reject symlinks to prevent signing arbitrary files (info leak)
    if path.is_symlink():
        raise ValueError(
            f"Receipt file is a symlink (refusing to sign): {receipt_path}"
        )

    # Cap file size before loading into memory.
    # verify_receipt_file has a 50 MB cap but sign_receipt_file did not,
    # allowing a 1 GB file to be loaded entirely into RAM.
    try:
        file_size = path.stat().st_size
    except OSError as e:
        raise ValueError(f"Cannot stat receipt file: {e}") from e
    if file_size > MAX_RECEIPT_FILE_SIZE:
        raise ValueError(
            f"Receipt file too large for signing ({file_size} bytes, max {MAX_RECEIPT_FILE_SIZE})"
        )

    receipt_bytes = path.read_bytes()

    # Validate content is JSON before sending to Sigstore
    try:
        json.loads(receipt_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError(
            f"Receipt file is not valid JSON (refusing to sign): {receipt_path}"
        )

    bundle_json = sign_receipt(receipt_bytes)

    bundle_path = str(path) + ".sigstore"
    fd = os.open(bundle_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    if _HAS_FCHMOD:
        os.fchmod(fd, 0o644)  # Force permissions regardless of umask
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(bundle_json)
    return bundle_path


def verify_receipt_signature(
    receipt_path: str,
    bundle_path: Optional[str] = None,
    expected_identity: Optional[str] = None,
    expected_issuer: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify a receipt's Sigstore signature bundle.

    Args:
        receipt_path: Path to the receipt JSON file.
        bundle_path: Path to the .sigstore bundle. If None, looks for
            <receipt_path>.sigstore.
        expected_identity: Expected signer identity (email or OIDC subject).
            If None, accepts any signer (UnsafeNoOp policy).
        expected_issuer: Expected OIDC issuer URL.

    Returns a dict with verification results.
    """
    rpath = Path(receipt_path)
    if not rpath.exists():
        return {"valid": False, "error": f"Receipt not found: {receipt_path}"}
    # Reject symlinks to prevent probing arbitrary files
    if rpath.is_symlink():
        return {
            "valid": False,
            "error": f"Receipt file is a symlink (refusing to verify): {receipt_path}",
        }

    if bundle_path is None:
        bundle_path = str(rpath) + ".sigstore"
    bpath = Path(bundle_path)
    if not bpath.exists():
        return {
            "valid": False,
            "error": f"Sigstore bundle not found: {bundle_path}",
        }
    # Reject symlinks for bundle path as well
    if bpath.is_symlink():
        return {
            "valid": False,
            "error": f"Bundle file is a symlink (refusing to verify): {bundle_path}",
        }

    # Reject oversized files to prevent memory exhaustion
    for fpath, label in [(rpath, "Receipt"), (bpath, "Bundle")]:
        try:
            fsize = fpath.stat().st_size
        except OSError as e:
            return {"valid": False, "error": f"Cannot stat {label.lower()}: {e}"}
        if fsize > MAX_RECEIPT_FILE_SIZE:
            return {
                "valid": False,
                "error": f"{label} too large ({fsize} bytes, max {MAX_RECEIPT_FILE_SIZE})",
            }

    try:
        from sigstore.models import Bundle
        from sigstore.verify import Verifier
        from sigstore.verify.policy import Identity, UnsafeNoOp
    except ImportError:
        raise RuntimeError(
            "Sigstore verification requires the 'sigstore' package.\n"
            "Install with: pip install sigstore"
        )

    try:
        receipt_bytes = rpath.read_bytes()
        bundle = Bundle.from_json(bpath.read_text(encoding="utf-8"))
        verifier = Verifier.production()

        if expected_identity:
            policy = Identity(
                identity=expected_identity,
                issuer=expected_issuer,
            )
        else:
            policy = UnsafeNoOp()

        verifier.verify_artifact(receipt_bytes, bundle, policy)

        return {
            "valid": True,
            "signature_valid": True,
            "receipt_path": str(receipt_path),
            "bundle_path": str(bundle_path),
            "policy": "identity" if expected_identity else "any",
        }
    except Exception as e:
        # Sanitize error to prevent leaking internal paths or OIDC details
        error_msg = str(e)
        # Strip potential file paths and tokens from error messages
        safe_error = error_msg.split("\n")[0][:200]  # First line, capped
        # Redact filesystem paths — previously missed here, unlike
        # _run_git and _sanitize_error which both apply this regex.
        safe_error = re.sub(r'/[\w./-]{5,}', '<path>', safe_error)
        return {
            "valid": False,
            "signature_valid": False,
            "error": safe_error,
        }
