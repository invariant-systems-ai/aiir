#!/usr/bin/env python3
"""
Generate _CONFUSABLE_TO_ASCII from Unicode TR39 confusables.txt.

Downloads the official Unicode Security Mechanisms confusables.txt and extracts
all single-codepoint → single-ASCII-letter/digit mappings that NFKC does NOT
already resolve.  Output is a Python dict literal ready to paste into _core.py.

Usage:
    python scripts/gen_confusables.py > /tmp/confusable_map.py

Source: https://www.unicode.org/Public/security/latest/confusables.txt
Reference: https://www.unicode.org/reports/tr39/ (Unicode Technical Standard #39)

Copyright 2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import re
import sys
import unicodedata
import urllib.request

CONFUSABLES_URL = "https://www.unicode.org/Public/security/latest/confusables.txt"


def fetch_confusables(url: str = CONFUSABLES_URL) -> str:
    """Download confusables.txt from Unicode Consortium."""
    with urllib.request.urlopen(url, timeout=30) as resp:
        return resp.read().decode("utf-8")


def parse_confusables(text: str) -> list[tuple[int, str, str, str]]:
    """Extract single-codepoint → single-ASCII-letter/digit mappings.

    Returns list of (source_codepoint, source_char, target_char, unicode_name).
    Only entries where NFKC(source) ≠ target are included.
    """
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"([0-9A-F ]+)\s*;\s*([0-9A-F ]+)\s*;", line)
        if not m:
            continue
        src_parts = m.group(1).strip().split()
        tgt_parts = m.group(2).strip().split()
        # Single codepoint → single codepoint only
        if len(src_parts) != 1 or len(tgt_parts) != 1:
            continue
        src_cp = int(src_parts[0], 16)
        tgt_cp = int(tgt_parts[0], 16)
        # Skip ASCII sources (we only need non-ASCII → ASCII)
        if src_cp < 0x80:
            continue
        tgt_chr = chr(tgt_cp)
        # Target must be ASCII letter or digit
        if not (tgt_chr.isascii() and (tgt_chr.isalpha() or tgt_chr.isdigit())):
            continue
        src_chr = chr(src_cp)
        # Skip entries that NFKC already resolves
        if unicodedata.normalize("NFKC", src_chr) == tgt_chr:
            continue
        name = unicodedata.name(src_chr, "UNKNOWN")
        entries.append((src_cp, src_chr, tgt_chr, name))
    return entries


def format_dict(entries: list[tuple[int, str, str, str]]) -> str:
    """Format entries as a Python dict literal."""
    # Sort by codepoint for deterministic, reviewable output
    entries.sort(key=lambda e: e[0])

    # Count scripts
    scripts: set[str] = set()
    for e in entries:
        name = unicodedata.name(chr(e[0]), "")
        parts = name.split()
        if parts:
            scripts.add(parts[0])

    lines = [
        "# Unicode TR39 confusable map — characters that NFKC does NOT resolve.",
        "# Source: Unicode Security Mechanisms for UTS #39, confusables.txt",
        "# URL: https://www.unicode.org/Public/security/latest/confusables.txt",
        "# Version: 17.0.0 (2025-07-22)",
        f"# Scope: {len(entries)} single-codepoint → ASCII letter/digit mappings across",
        f"#         {len(scripts)} scripts (Cyrillic, Greek, Armenian, Cherokee, Coptic,",
        f"#         Lisu, Warang Citi, Mathematical, and {len(scripts) - 8}+ others).",
        "# Generation: Programmatically extracted — see scripts/gen_confusables.py.",
        "# Only entries where NFKC(source) ≠ target are included.",
        "_CONFUSABLE_TO_ASCII = {",
    ]
    for src_cp, src_chr, tgt_chr, name in entries:
        short = name[:52]
        if src_cp <= 0xFFFF:
            lines.append(f'    "\\u{src_cp:04X}": "{tgt_chr}",  # {short}')
        else:
            lines.append(f'    "\\U{src_cp:08X}": "{tgt_chr}",  # {short}')
    lines.append("}")
    return "\n".join(lines) + "\n"


def main() -> None:
    print("Downloading confusables.txt ...", file=sys.stderr)
    text = fetch_confusables()
    entries = parse_confusables(text)
    output = format_dict(entries)
    print(output)
    print(
        f"Generated {len(entries)} entries from confusables.txt",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
