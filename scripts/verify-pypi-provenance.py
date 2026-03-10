#!/usr/bin/env python3
"""
Verify PEP 740 attestations for AIIR releases via the PyPI Integrity API.

Queries PyPI's Integrity API endpoint to retrieve and display digital
attestations (SLSA provenance + PyPI Publish predicates) for every
wheel and source distribution in a given AIIR release.

Usage:
    # Verify the latest release
    python scripts/verify-pypi-provenance.py

    # Verify a specific version
    python scripts/verify-pypi-provenance.py 1.2.1

    # Strict mode — exit 1 if any artifact lacks attestations
    python scripts/verify-pypi-provenance.py --strict

    # Show full attestation JSON
    python scripts/verify-pypi-provenance.py --verbose

Exit codes:
    0  All artifacts have attestations (or non-strict mode)
    1  Missing attestations in strict mode, or network/API error

Requires: Python 3.9+ (stdlib only — zero dependencies)

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple

PYPI_PROJECT = "aiir"
PYPI_JSON_URL = "https://pypi.org/pypi/{project}/{version}/json"
PYPI_INTEGRITY_URL = "https://pypi.org/integrity/{project}/{version}/{filename}/provenance"
PYPI_LATEST_URL = "https://pypi.org/pypi/{project}/json"

# Timeout for HTTP requests (seconds).
HTTP_TIMEOUT = 30


def _fetch_json(url: str) -> Dict[str, Any]:
    """Fetch JSON from a URL.  Raises on HTTP or parse errors."""
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _fetch_json_safe(url: str) -> Tuple[Optional[Dict[str, Any]], int]:
    """Fetch JSON from a URL, returning (data, http_code).

    Returns (None, code) on HTTP errors instead of raising.
    """
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data, resp.status
    except urllib.error.HTTPError as e:
        return None, e.code
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return None, 0


def get_latest_version() -> str:
    """Fetch the latest version of the project from PyPI."""
    url = PYPI_LATEST_URL.format(project=PYPI_PROJECT)
    data = _fetch_json(url)
    return data["info"]["version"]


def get_release_files(version: str) -> List[Dict[str, Any]]:
    """Fetch the list of release files for a given version."""
    url = PYPI_JSON_URL.format(project=PYPI_PROJECT, version=version)
    data = _fetch_json(url)
    return data.get("urls", [])


def check_attestation(version: str, filename: str) -> Dict[str, Any]:
    """Query the PyPI Integrity API for attestations on a specific file.

    Returns a dict with:
      - filename: str
      - has_attestations: bool
      - http_code: int
      - attestation_count: int
      - predicates: list of predicate types found
      - raw: full JSON response (if available)
    """
    url = PYPI_INTEGRITY_URL.format(
        project=PYPI_PROJECT, version=version, filename=filename
    )
    data, code = _fetch_json_safe(url)

    result: Dict[str, Any] = {
        "filename": filename,
        "has_attestations": False,
        "http_code": code,
        "attestation_count": 0,
        "predicates": [],
        "raw": data,
    }

    if data is None or code != 200:
        return result

    # PEP 740 response format: attestation_bundles or attestations array
    bundles = data.get("attestation_bundles", data.get("attestations", []))
    if not isinstance(bundles, list):
        return result

    result["has_attestations"] = len(bundles) > 0
    result["attestation_count"] = len(bundles)

    # Extract predicate types from attestation bundles
    predicates = []
    for bundle in bundles:
        if isinstance(bundle, dict):
            # Direct attestation format
            pred_type = bundle.get("predicate_type", "")
            if pred_type:
                predicates.append(pred_type)
            # Bundle format with nested attestations
            for att in bundle.get("attestations", []):
                if isinstance(att, dict):
                    pt = att.get("predicate_type", "")
                    if pt:
                        predicates.append(pt)
    result["predicates"] = predicates

    return result


def verify_release(
    version: str,
    *,
    strict: bool = False,
    verbose: bool = False,
) -> bool:
    """Verify PEP 740 attestations for all files in a release.

    Returns True if all files have attestations, False otherwise.
    """
    print(f"Verifying PEP 740 attestations for {PYPI_PROJECT}=={version}")
    print(f"PyPI: https://pypi.org/project/{PYPI_PROJECT}/{version}/")
    print()

    try:
        files = get_release_files(version)
    except Exception as e:
        print(f"ERROR: Could not fetch release info from PyPI: {e}", file=sys.stderr)
        return False

    if not files:
        print(f"ERROR: No files found for {PYPI_PROJECT}=={version}", file=sys.stderr)
        return False

    total = len(files)
    attested = 0
    results = []

    for file_info in files:
        filename = file_info["filename"]
        packagetype = file_info.get("packagetype", "unknown")
        size = file_info.get("size", 0)
        sha256 = file_info.get("digests", {}).get("sha256", "unknown")

        print(f"  {filename}")
        print(f"    Type: {packagetype} | Size: {size:,} bytes")
        print(f"    SHA-256: {sha256[:16]}...")

        result = check_attestation(version, filename)
        results.append(result)

        if result["has_attestations"]:
            attested += 1
            count = result["attestation_count"]
            print(f"    Attestations: {count} found")
            if result["predicates"]:
                for pred in result["predicates"]:
                    print(f"      - {pred}")
            else:
                print(f"      (predicate types not enumerated in response)")
        elif result["http_code"] == 404:
            print(f"    Attestations: none (Integrity API returned 404)")
        elif result["http_code"] == 0:
            print(f"    Attestations: could not reach Integrity API")
        else:
            print(f"    Attestations: none (HTTP {result['http_code']})")

        if verbose and result["raw"]:
            print(f"    Raw response:")
            print(f"      {json.dumps(result['raw'], indent=2)[:500]}")

        print()

    # Summary
    print("=" * 60)
    print(f"Summary: {attested}/{total} artifacts have PEP 740 attestations")
    print()

    if attested == total and total > 0:
        print("All release artifacts are attested.")
        print("Supply chain: OIDC identity (Trusted Publishing) -> PyPI attestation")
        return True
    elif attested > 0:
        print(f"Partial coverage: {attested}/{total} attested.")
        if not strict:
            print("Run with --strict to fail on incomplete attestation coverage.")
        return not strict
    else:
        print("No attestations found.")
        print()
        print("This may indicate:")
        print("  - The release was published before PEP 740 support was enabled")
        print("  - Attestations are still propagating (try again in a few minutes)")
        print("  - The release was not published via Trusted Publishing (OIDC)")
        return not strict


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify PEP 740 attestations for AIIR releases on PyPI.",
        epilog=(
            "Examples:\n"
            "  %(prog)s              # verify latest release\n"
            "  %(prog)s 1.2.1        # verify specific version\n"
            "  %(prog)s --strict     # exit 1 if any artifact lacks attestations\n"
            "  %(prog)s --verbose    # show raw attestation JSON\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "version",
        nargs="?",
        default=None,
        help="Version to verify (default: latest on PyPI)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any artifact lacks attestations",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show full attestation JSON responses",
    )
    args = parser.parse_args()

    version = args.version
    if version is None:
        try:
            version = get_latest_version()
            print(f"Latest version on PyPI: {version}")
            print()
        except Exception as e:
            print(f"ERROR: Could not fetch latest version: {e}", file=sys.stderr)
            sys.exit(1)

    ok = verify_release(version, strict=args.strict, verbose=args.verbose)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
