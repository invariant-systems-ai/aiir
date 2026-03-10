#!/usr/bin/env python3
"""
sync-version.py — Self-healing version synchronisation for AIIR.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0

Reads the single source of truth (__version__ in aiir/__init__.py) and
patches every file that embeds the version string.  Designed to be called
from:

  1. pre-commit (--check → exits 1 on drift, no writes)
  2. CI         (--check → same)
  3. release    (--fix   → patches in-place)
  4. manually   (--fix   → patches in-place)

Usage:
  python scripts/sync-version.py --check            # dry-run (CI / pre-commit)
  python scripts/sync-version.py --fix              # write patches (release)
  python scripts/sync-version.py --fix --website-dir ../invariantsystems.io

Zero dependencies — standard library only.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import NamedTuple

# ── Source of truth ──────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
INIT_PY = REPO_ROOT / "aiir" / "__init__.py"

# ── Replacement rules ───────────────────────────────────────────────
# Each rule is (relative_path, regex_pattern, replacement_template).
# The regex MUST have a single named group `(?P<ver>...)` that captures
# the old version string.  The replacement_template uses {version} for
# the new version.


class Rule(NamedTuple):
    path: str
    pattern: str
    replacement: str


# --- AIIR repo rules ------------------------------------------------
AIIR_RULES: list[Rule] = [
    # mcp-manifest.json  →  "version": "X.Y.Z"
    Rule(
        "mcp-manifest.json",
        r'"version":\s*"(?P<ver>\d+\.\d+\.\d+)"',
        '"version": "{version}"',
    ),
    # docs/api.md  →  **Version**: X.Y.Z
    Rule(
        "docs/api.md",
        r"\*\*Version\*\*:\s*(?P<ver>\d+\.\d+\.\d+)",
        "**Version**: {version}",
    ),
    # README.md  →  rev: vX.Y.Z
    Rule(
        "README.md",
        r"rev:\s*v(?P<ver>\d+\.\d+\.\d+)",
        "rev: v{version}",
    ),
    # README.md  →  | `version` | string | `X.Y.Z`
    Rule(
        "README.md",
        r"\| `version`\s*\| string\s*\| `(?P<ver>\d+\.\d+\.\d+)`",
        "| `version` | string | `{version}`",
    ),
    # README.md  →  raw.githubusercontent.com/.../vX.Y.Z/templates/
    Rule(
        "README.md",
        r"raw\.githubusercontent\.com/invariant-systems-ai/aiir/v(?P<ver>\d+\.\d+\.\d+)/templates/",
        "raw.githubusercontent.com/invariant-systems-ai/aiir/v{version}/templates/",
    ),
    # README.md  →  ref: 'vX.Y.Z'
    Rule(
        "README.md",
        r"ref:\s*'v(?P<ver>\d+\.\d+\.\d+)'",
        "ref: 'v{version}'",
    ),
    # templates/receipt/template.yml  →  default: "X.Y.Z"
    Rule(
        "templates/receipt/template.yml",
        r'default:\s*"(?P<ver>\d+\.\d+\.\d+)"',
        'default: "{version}"',
    ),
    # templates/gitlab-ci.yml  →  raw.githubusercontent.com/.../vX.Y.Z/
    Rule(
        "templates/gitlab-ci.yml",
        r"raw\.githubusercontent\.com/invariant-systems-ai/aiir/v(?P<ver>\d+\.\d+\.\d+)/",
        "raw.githubusercontent.com/invariant-systems-ai/aiir/v{version}/",
    ),
    # templates/gitlab-ci.yml  →  ref: 'vX.Y.Z'
    Rule(
        "templates/gitlab-ci.yml",
        r"ref:\s*'v(?P<ver>\d+\.\d+\.\d+)'",
        "ref: 'v{version}'",
    ),
    # templates/gitlab-ci.yml  →  AIIR_VERSION: "X.Y.Z"
    Rule(
        "templates/gitlab-ci.yml",
        r'AIIR_VERSION:\s*"(?P<ver>\d+\.\d+\.\d+)"',
        'AIIR_VERSION: "{version}"',
    ),
    # sdks/js/package.json  →  "version": "X.Y.Z"
    Rule(
        "sdks/js/package.json",
        r'"version":\s*"(?P<ver>\d+\.\d+\.\d+)"',
        '"version": "{version}"',
    ),
    # contrib/launch-post-devto.md  →  rev: vX.Y.Z
    Rule(
        "contrib/launch-post-devto.md",
        r"rev:\s*v(?P<ver>\d+\.\d+\.\d+)",
        "rev: v{version}",
    ),
    # examples/gitlab-demo/.gitlab-ci.yml  →  AIIR_VERSION: "X.Y.Z"
    Rule(
        "examples/gitlab-demo/.gitlab-ci.yml",
        r'AIIR_VERSION:\s*"(?P<ver>\d+\.\d+\.\d+)"',
        'AIIR_VERSION: "{version}"',
    ),
    # examples/gitlab-demo/README.md  →  raw.githubusercontent.com/.../vX.Y.Z/
    Rule(
        "examples/gitlab-demo/README.md",
        r"raw\.githubusercontent\.com/invariant-systems-ai/aiir/v(?P<ver>\d+\.\d+\.\d+)/",
        "raw.githubusercontent.com/invariant-systems-ai/aiir/v{version}/",
    ),
]

# --- Website repo rules (require --website-dir) ---------------------
WEBSITE_RULES: list[Rule] = [
    # stats.json  →  "version": "X.Y.Z"
    Rule(
        "stats.json",
        r'"version":\s*"(?P<ver>\d+\.\d+\.\d+)"',
        '"version": "{version}"',
    ),
    # .well-known/mcp.json  →  "version": "X.Y.Z"
    Rule(
        ".well-known/mcp.json",
        r'"version":\s*"(?P<ver>\d+\.\d+\.\d+)"',
        '"version": "{version}"',
    ),
    # docs.html  →  <span data-aiir-version>X.Y.Z</span>
    Rule(
        "docs.html",
        r"data-aiir-version>(?P<ver>\d+\.\d+\.\d+)</span>",
        "data-aiir-version>{version}</span>",
    ),
    # index.html  →  class="version-code">vX.Y.Z</code>
    Rule(
        "index.html",
        r'class="version-code">v(?P<ver>\d+\.\d+\.\d+)</code>',
        'class="version-code">v{version}</code>',
    ),
]


# ── Helpers ──────────────────────────────────────────────────────────


def get_version() -> str:
    """Read __version__ from aiir/__init__.py."""
    text = INIT_PY.read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"(?P<ver>\d+\.\d+\.\d+)"', text)
    if not match:
        print(f"❌ Could not parse __version__ from {INIT_PY}", file=sys.stderr)
        sys.exit(2)
    return match.group("ver")


def apply_rules(
    rules: list[Rule],
    root: Path,
    version: str,
    *,
    fix: bool,
) -> list[str]:
    """
    Check / fix version references.

    Returns a list of human-readable drift messages (empty = all in sync).
    """
    drifts: list[str] = []

    for rule in rules:
        fpath = root / rule.path
        if not fpath.exists():
            # File may not exist in all checkouts (e.g. website dir not present).
            continue

        text = fpath.read_text(encoding="utf-8")
        pattern = re.compile(rule.pattern)

        matches = list(pattern.finditer(text))
        if not matches:
            drifts.append(f"  ⚠️  {rule.path}: pattern not found (rule may be stale)")
            continue

        stale = [m for m in matches if m.group("ver") != version]
        if not stale:
            continue

        old_versions = {m.group("ver") for m in stale}
        drifts.append(
            f"  ✗ {rule.path}: found {', '.join(sorted(old_versions))} → want {version}"
            f" ({len(stale)} occurrence{'s' if len(stale) != 1 else ''})"
        )

        if fix:
            # Replace all occurrences of the pattern with the correct version.
            new_text = pattern.sub(
                lambda m: rule.replacement.format(version=version),
                text,
            )
            fpath.write_text(new_text, encoding="utf-8")

    return drifts


# ── Main ─────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Synchronise version strings across the AIIR repo.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check",
        action="store_true",
        help="Dry-run: report drift and exit 1 if any found.",
    )
    mode.add_argument(
        "--fix",
        action="store_true",
        help="Patch all files in-place to match __version__.",
    )
    parser.add_argument(
        "--version",
        default=None,
        help="Override version (default: read from aiir/__init__.py).",
    )
    parser.add_argument(
        "--website-dir",
        default=None,
        help="Path to invariantsystems.io checkout (optional).",
    )
    args = parser.parse_args()

    version = args.version or get_version()
    print(f"🔖 Source of truth: {version}")

    all_drifts: list[str] = []

    # AIIR repo
    drifts = apply_rules(AIIR_RULES, REPO_ROOT, version, fix=args.fix)
    all_drifts.extend(drifts)

    # Website repo (optional)
    if args.website_dir:
        website_root = Path(args.website_dir).resolve()
        if not website_root.exists():
            print(f"⚠️  Website dir not found: {website_root}", file=sys.stderr)
        else:
            drifts = apply_rules(WEBSITE_RULES, website_root, version, fix=args.fix)
            all_drifts.extend(drifts)

    if all_drifts:
        action = "Fixed" if args.fix else "Drift found"
        print(f"\n{'🔧' if args.fix else '❌'} {action}:")
        for line in all_drifts:
            print(line)
        if args.fix:
            print(f"\n✅ All version references updated to {version}")
            return 0
        else:
            print("\nRun `python scripts/sync-version.py --fix` to auto-correct.")
            return 1
    else:
        print(f"✅ All version references are at {version}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
