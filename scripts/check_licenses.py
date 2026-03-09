#!/usr/bin/env python3
"""Verify that all dependency licenses are policy-compliant.

Used by the Security CI workflow (license-check job).
Reads the JSON output of pip-licenses and verifies every package's
license string contains at least one approved term.
"""

from __future__ import annotations

import json
import sys

# Substring terms — if ANY of these appears in the license string,
# the package is considered approved.  This handles both human-readable
# names ("MIT License") and SPDX compound expressions ("Apache-2.0 OR
# BSD-3-Clause") without needing an exact-match allow-list.
APPROVED_TERMS: list[str] = [
    "Apache",
    "MIT",
    "BSD",
    "ISC",
    "PSF",
    "Python Software Foundation",
    "Mozilla Public License",
    "MPL",
    "Public Domain",
    "Unlicense",
    "HPND",  # Historical Permission Notice and Disclaimer
]

# Packages to skip (e.g. the project itself, or packages whose metadata
# reports UNKNOWN but are verified Apache-2.0 / MIT upstream)
SKIP_PACKAGES: set[str] = {"aiir", "sigstore-models"}


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: check_licenses.py <licenses.json>", file=sys.stderr)
        return 2

    with open(sys.argv[1]) as f:
        pkgs = json.load(f)

    failed: list[str] = []
    for p in pkgs:
        name = p["Name"]
        lic = p.get("License", "UNKNOWN")
        if name in SKIP_PACKAGES:
            continue
        if not any(term in lic for term in APPROVED_TERMS):
            ver = p.get("Version", "?")
            failed.append(f"  {name}:{ver}  =>  {lic}")

    if failed:
        print("❌ Unapproved licenses found:", file=sys.stderr)
        for line in failed:
            print(line, file=sys.stderr)
        return 1

    print(f"✅ All {len(pkgs)} dependency licenses are policy-compliant")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
