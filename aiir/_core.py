"""
AIIR internal core — constants, encoding helpers, git operations, hashing.

This module contains the foundational utilities shared across all AIIR
submodules. It is NOT part of the public API; import from ``aiir.cli`` instead.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

# Structured logging for observability/debuggability.
# Users enable with --verbose or AIIR_LOG_LEVEL=DEBUG.
logger = logging.getLogger("aiir")

# Windows does not have os.fchmod — guard all permission-setting calls.
_HAS_FCHMOD = hasattr(os, "fchmod")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RECEIPT_SCHEMA_VERSION = "aiir/commit_receipt.v1"

# Single source of truth — __version__ lives in __init__.py only.
from aiir import __version__ as CLI_VERSION

# Safety limit: max commits to receipt in a single range (DoS prevention)
MAX_RECEIPTS_PER_RANGE = 1000

# Safety limit: max file size for receipt verification (50 MB)
MAX_RECEIPT_FILE_SIZE = 50 * 1024 * 1024

# GitHub Actions step summary size limit (1 MB matches GitHub's own limit).
MAX_SUMMARY_SIZE = 1024 * 1024

# Default ledger directory and filenames.
LEDGER_DIR = ".aiir"
LEDGER_FILE = "receipts.jsonl"
INDEX_FILE = "index.json"
CONFIG_FILE = "config.json"

# Default subprocess timeout (seconds) to prevent indefinite hangs
GIT_TIMEOUT = 300

# Prevent auth hangs (GIT_TERMINAL_PROMPT) and credential helpers (GIT_ASKPASS)
# in CI environments where no human is present.
_GIT_SAFE_ENV: Dict[str, str] = {
    **os.environ,
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "",
}


# ---------------------------------------------------------------------------
# Encoding-safe symbol helpers
# ---------------------------------------------------------------------------
# Emoji above U+2700 crash on Windows cmd.exe (cp437/cp1252), CI runners with
# LANG=C, and piped stderr (encoding=ascii).  Box-drawing chars (U+2500 range)
# survive cp437 but crash on cp1252 (PowerShell default) and ASCII/latin-1.
# We probe sys.stderr.encoding once and fall back to plain ASCII when needed.

_EMOJI: Dict[str, Tuple[str, str]] = {
    "ok":     ("\u2705", "[ok]"),       # ✅
    "error":  ("\u274c", "[error]"),     # ❌
    "hint":   ("\U0001f4a1", "[hint]"),  # 💡
    "ai":     ("\U0001f916", "[AI]"),    # 🤖
    "signed": ("\U0001f58a\ufe0f", "[signed]"),  # 🖊️
    "tip":    ("\U0001f4dd", "[tip]"),   # 📝
    "shrug":  ("\U0001f937", "[info]"),  # 🤷
    "check":  ("\u2714", "ok"),          # ✔
}

# Box-drawing glyphs used in format_receipt_pretty.  These survive on cp437
# (DOS/Windows Console Host) but crash on cp1252 (PowerShell default),
# latin-1, and ASCII.  Fall back to safe ASCII art (+, -, |).
_BOX: Dict[str, Tuple[str, str]] = {
    "tl":   ("\u250c", "+"),   # ┌  top-left corner
    "vl":   ("\u2502", "|"),   # │  vertical line
    "bl":   ("\u2514", "+"),   # └  bottom-left corner
    "hl":   ("\u2500", "-"),   # ─  horizontal line
}


def _can_encode(probe: str) -> bool:
    """Return True if stderr can encode *probe* without error."""
    try:
        enc = getattr(sys.stderr, "encoding", None) or "ascii"
        probe.encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


# Resolved once at import time; overridable in tests via monkeypatching.
_USE_EMOJI: bool = _can_encode("\u2705\U0001f916")
_USE_BOXDRAW: bool = _can_encode("\u250c\u2500\u2502\u2514")


def _e(name: str) -> str:
    """Return emoji glyph if the terminal supports it, else ASCII fallback."""
    pair = _EMOJI.get(name)
    if pair is None:
        return ""
    return pair[0] if _USE_EMOJI else pair[1]


def _b(name: str) -> str:
    """Return box-drawing glyph if the terminal supports it, else ASCII."""
    pair = _BOX.get(name)
    if pair is None:
        return ""
    return pair[0] if _USE_BOXDRAW else pair[1]


# Common Unicode confusables that NFKC normalization does NOT resolve.
# Cyrillic/Greek letters visually identical to Latin — used to bypass AI detection.
_CONFUSABLE_TO_ASCII = {
    "\u0430": "a",  # Cyrillic а → Latin a
    "\u0410": "A",  # Cyrillic А → Latin A
    "\u0435": "e",  # Cyrillic е → Latin e
    "\u0415": "E",  # Cyrillic Е → Latin E
    "\u043e": "o",  # Cyrillic о → Latin o
    "\u041e": "O",  # Cyrillic О → Latin O
    "\u0441": "c",  # Cyrillic с → Latin c
    "\u0421": "C",  # Cyrillic С → Latin C
    "\u0440": "p",  # Cyrillic р → Latin p
    "\u0420": "P",  # Cyrillic Р → Latin P
    "\u0456": "i",  # Cyrillic і → Latin i
    "\u0406": "I",  # Cyrillic І → Latin I
    "\u0443": "u",  # Cyrillic у → Latin u
    "\u0423": "U",  # Cyrillic У → Latin U
    "\u0445": "x",  # Cyrillic х → Latin x
    "\u0425": "X",  # Cyrillic Х → Latin X
    "\u04bb": "h",  # Cyrillic һ → Latin h
    "\u0455": "s",  # Cyrillic ѕ → Latin s
    "\u0458": "j",  # Cyrillic ј → Latin j
    "\u0501": "d",  # Cyrillic ԁ → Latin d
    # Removed \u0491 (ґ→g) and \u0510 (Ԑ→q) — inaccurate visual matches.
    "\u03bf": "o",  # Greek ο → Latin o
    "\u03b1": "a",  # Greek α → Latin a (close match)
    "\u0391": "A",  # Greek Α → Latin A
    "\u0392": "B",  # Greek Β → Latin B
    "\u0395": "E",  # Greek Ε → Latin E
    "\u0397": "H",  # Greek Η → Latin H
    "\u0399": "I",  # Greek Ι → Latin I
    "\u039a": "K",  # Greek Κ → Latin K
    "\u039c": "M",  # Greek Μ → Latin M
    "\u039d": "N",  # Greek Ν → Latin N
    "\u039f": "O",  # Greek Ο → Latin O
    "\u03a1": "P",  # Greek Ρ → Latin P
    "\u03a4": "T",  # Greek Τ → Latin T
    "\u03a5": "Y",  # Greek Υ → Latin Y
    "\u03a7": "X",  # Greek Χ → Latin X
    "\u03b5": "e",  # Greek ε → close to e
}

# Unicode dash/hyphen variants that NFKC does NOT normalize to ASCII '-'.
# These are the delimiter in "co-authored-by" — missing them is a detection bypass.
_DASH_TO_ASCII = {
    "\u2010": "-",  # Hyphen (‐)
    "\u2011": "-",  # Non-breaking hyphen (‑)
    "\u2013": "-",  # En dash (–)
    "\u2014": "-",  # Em dash (—)
    "\u2015": "-",  # Horizontal bar (―)
    "\u2212": "-",  # Minus sign (−)
    "\u00AD": "-",  # Soft hyphen
    "\uFE58": "-",  # Small em dash (﹘)
    "\uFE63": "-",  # Small hyphen-minus (﹣) — NFKC covers this but be explicit
    "\uFF0D": "-",  # Fullwidth hyphen-minus (－) — NFKC covers this but be explicit
}


def _validate_ref(ref: str) -> str:
    """Reject refs that look like git options, path traversal, or shell metacharacters."""
    if ref.lstrip().startswith("-"):
        raise ValueError(f"Invalid git ref (looks like an option): {ref!r}")
    if "\x00" in ref:
        raise ValueError(f"Invalid git ref (contains NUL byte): {ref!r}")
    if "\n" in ref or "\r" in ref:
        raise ValueError(f"Invalid git ref (contains newline/CR): {ref!r}")
    if len(ref) > 1024:
        raise ValueError(f"Git ref too long ({len(ref)} chars, max 1024)")
    # Reject path traversal sequences — git rejects these too, but
    # defense-in-depth means catching them before they reach the subprocess.
    # IMPORTANT: '..' and '...' are valid git range operators (main..HEAD,
    # main...HEAD), so only reject path-traversal patterns like '../' or '/../'.
    if "/../" in ref or ref.startswith("../"):
        raise ValueError(f"Invalid git ref (contains path traversal): {ref!r}")
    # Reject shell metacharacters that have no place in a git ref.
    _SHELL_METACHARS = set(";&|$`!><{}()")
    found = _SHELL_METACHARS.intersection(ref)
    if found:
        raise ValueError(
            f"Invalid git ref (contains shell metacharacters {found!r}): {ref!r}"
        )
    return ref


def _sanitize_md(text: str) -> str:
    """Sanitize text for safe inclusion in GitHub Markdown step summaries.

    Escapes: \\ & < > | ` [ ! * _ ~ :// and dangerous Unicode (bidi, Cc, etc.).
    """
    # Strip dangerous Unicode control characters (RTL override, etc.)
    # Use targeted deny-list instead of blanket Cf strip, since we
    # intentionally use ZWSP (U+200B) below for autolink breaking.
    _DANGEROUS_CATEGORIES = {"Cc"}  # C0/C1 control codes
    _DANGEROUS_CODEPOINTS = {
        "\u200E", "\u200F",          # LRM, RLM
        "\u200C", "\u200D",          # ZWNJ, ZWJ (homoglyph risk)
        "\u202A", "\u202B", "\u202C", "\u202D", "\u202E",  # Bidi overrides
        "\u2066", "\u2067", "\u2068", "\u2069",              # Bidi isolates
        "\u00AD",                      # Soft hyphen
        "\uFEFF",                      # BOM / ZWNBSP
    }
    text = "".join(
        c for c in text
        if unicodedata.category(c) not in _DANGEROUS_CATEGORIES
        and c not in _DANGEROUS_CODEPOINTS
    )
    # Escape & → &amp; FIRST so that pre-encoded HTML entities
    # (e.g., &lt;script&gt;) become &amp;lt; and are displayed literally, not
    # decoded back to <script> by GFM renderers.
    text = text.replace("&", "&amp;")
    # Escape backslashes BEFORE all \-based escapes.  Without
    # this, a commit subject containing \| survives as \\| in the output,
    # and GFM interprets \\\\ as a literal backslash followed by | as a
    # pipe delimiter — breaking the summary table structure.  Similarly,
    # \* \_ \~ would bypass the emphasis escaping below.
    text = text.replace("\\", "\\\\")
    text = text.replace("|", "\\|")
    text = text.replace("`", "\\`")
    text = text.replace("[", "\\[")
    text = text.replace("!", "\\!")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    # Escape GFM emphasis/strikethrough markers to prevent
    # formatting injection in table cells (*bold*, _italic_, ~~strike~~).
    text = text.replace("*", "\\*")
    text = text.replace("_", "\\_")
    text = text.replace("~", "\\~")
    # Break GFM autolink detection to prevent phishing links in summaries
    text = text.replace("://", "\u200B://")
    return text


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class CommitInfo:
    """Parsed git commit metadata."""

    sha: str
    author_name: str
    author_email: str
    author_date: str
    committer_name: str
    committer_email: str
    committer_date: str
    subject: str
    body: str
    diff_stat: str
    diff_hash: str  # SHA-256 of the full diff
    files_changed: List[str] = field(default_factory=list)
    ai_signals_detected: List[str] = field(default_factory=list)
    is_ai_authored: bool = False
    bot_signals_detected: List[str] = field(default_factory=list)
    is_bot_authored: bool = False
    # Structured authorship classification — first-class taxonomy.
    # Values: "human", "ai-assisted", "bot-generated", "ai+bot", "unknown".
    # Derived from is_ai_authored / is_bot_authored at detection time.
    authorship_class: str = "human"


# ---------------------------------------------------------------------------
# Terminal escape stripping
# ---------------------------------------------------------------------------


def _strip_terminal_escapes(text: str) -> str:
    """Strip ANSI escape sequences and ASCII control chars from text (R5-10).

    Prevents terminal injection via crafted commit subjects or author names
    (e.g., overwriting lines with ESC[A, changing colors, setting title).
    """
    # Strip ANSI CSI sequences (ESC[...X) and OSC sequences (ESC]...BEL/ST)
    # CSI final byte is 0x40-0x7E per ECMA-48, not just [A-Za-z].
    # Includes @, ~, {, |, } etc. (e.g., ESC[2~ = Insert key).
    text = re.sub(r'\x1b\[[0-9;]*[@-~]', '', text)
    text = re.sub(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)', '', text)
    # Strip PM (ESC ^...ST) and APC (ESC _...ST) sequences.
    # Also strip SOS (ESC X...ST) and DCS (ESC P...ST) sequences.
    # ECMA-48 §5.6 defines six C1 control strings; we now cover all of them.
    # ST terminator is now optional — unterminated control strings
    # (payload with no ESC \) are also stripped to prevent payload leakage.
    text = re.sub(r'\x1b[\^_XP][^\x1b]*(?:\x1b\\)?', '', text)
    # Strip remaining control characters:
    # - C0 range (0x00-0x1F except tab)
    # - DEL (0x7F) — erases characters in some terminals
    # 8-bit C1 controls (0x80-0x9F) — single-byte equivalents of
    # ESC-based C1 sequences (e.g., U+009B = CSI, U+0090 = DCS). Some terminals
    # interpret these as control sequences even in UTF-8 mode.
    text = ''.join(
        c for c in text
        if (ord(c) >= 0x20 or c == '\t')
        and ord(c) != 0x7F
        and not (0x80 <= ord(c) <= 0x9F)
    )
    return text


# ---------------------------------------------------------------------------
# Git helpers (subprocess, no dependencies)
# ---------------------------------------------------------------------------


def _run_git(args: List[str], cwd: Optional[str] = None) -> str:
    """Run a git command and return stdout."""
    logger.debug("git %s (cwd=%s)", " ".join(args[:3]), cwd or os.getcwd())
    result = subprocess.run(
        ["git", "--no-optional-locks"] + args,
        cwd=cwd or os.getcwd(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",  # Explicit UTF-8 — git outputs UTF-8 but Windows defaults to cp1252
        errors="replace",   # Replace undecodable bytes rather than crash
        check=False,
        timeout=GIT_TIMEOUT,  # Prevent indefinite hangs
        env=_GIT_SAFE_ENV,  # Prevent auth hangs
    )
    if result.returncode != 0:
        # Truncate stderr and redact command args to prevent leaking
        # internal format strings, paths, or auth details
        stderr_safe = result.stderr.strip().split('\n')[0][:200]
        # Redact anything that looks like a filesystem path to
        # prevent leaking internal directory structure in error messages.
        stderr_safe = re.sub(r'/[\w./-]{5,}', '<path>', stderr_safe)
        # Strip terminal escape sequences — a crafted ref name
        # (e.g., containing ESC[2J) would be echoed in git's stderr and
        # survive the truncation + path-redaction above.
        stderr_safe = _strip_terminal_escapes(stderr_safe)
        subcmd = args[0] if args else "command"
        raise RuntimeError(f"git {subcmd} failed: {stderr_safe}")
    return result.stdout


# ---------------------------------------------------------------------------
# Hashing and serialization
# ---------------------------------------------------------------------------


def _sha256(data: str) -> str:
    """SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _canonical_json(obj: Any) -> str:
    """Deterministic JSON serialization (sorted keys, no whitespace).

    Uses an explicit depth limit instead of relying on Python's recursion limit.
    Prevents stack overflow from deeply nested JSON structures.
    """
    _check_json_depth(obj, max_depth=64)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    )


# Explicit depth checker for JSON structures.
_MAX_JSON_DEPTH = 64


def _check_json_depth(obj: Any, max_depth: int = _MAX_JSON_DEPTH) -> None:
    """Raise ValueError if a JSON structure exceeds max_depth nesting.

    Uses iterative stack-based traversal instead of recursion.
    The recursive version added to Python's call stack alongside any caller
    frames (e.g., MCP server → handler → verify → canonical_json → check),
    making the 64-level limit fragile under deep call chains.
    Removed dead `_current` parameter from old recursive API.
    """
    stack = [(obj, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise ValueError(f"JSON structure exceeds maximum depth of {max_depth}")
        if isinstance(node, dict):
            for v in node.values():
                stack.append((v, depth + 1))
        elif isinstance(node, (list, tuple)):
            for item in node:
                stack.append((item, depth + 1))


def _hash_diff_streaming(parent: str, sha: str, cwd: Optional[str] = None) -> str:
    """Stream-hash a git diff to avoid loading it all into memory.

    R3-02: stderr goes to DEVNULL to prevent bidirectional pipe deadlock.
    (If stdout and stderr are both PIPE and stderr fills the 64KB buffer,
    git blocks on stderr write while Python blocks on stdout read.)
    """
    # --no-ext-diff and --no-textconv prevent malicious .gitattributes
    # from invoking custom diff drivers/textconv filters that could inject
    # arbitrary data into the diff hash.
    proc = subprocess.Popen(
        ["git", "--no-optional-locks", "diff", "--no-ext-diff", "--no-textconv", parent, sha],
        cwd=cwd or os.getcwd(),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=_GIT_SAFE_ENV,  # Consistent with _run_git
    )
    h = hashlib.sha256()
    # Track elapsed time to enforce timeout
    deadline = time.monotonic() + GIT_TIMEOUT
    try:
        while True:
            if time.monotonic() > deadline:
                proc.kill()
                proc.wait()  # Reap child to prevent zombie process
                raise RuntimeError(
                    f"git diff {parent} {sha} timed out after {GIT_TIMEOUT}s"
                )
            chunk = proc.stdout.read(65536)
            if not chunk:
                break
            h.update(chunk)
    except RuntimeError:
        raise  # Re-raise timeout error (already cleaned up above)
    except Exception:
        # Unexpected I/O error — kill and reap the subprocess
        proc.kill()
        proc.wait()
        raise
    finally:
        proc.stdout.close()
    # Final wait with timeout — kill if git hangs during cleanup.
    _killed_for_cleanup = False
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        _killed_for_cleanup = True
    if proc.returncode != 0 and not _killed_for_cleanup:
        raise RuntimeError(f"git diff {parent} {sha} failed (exit code {proc.returncode})")
    return "sha256:" + h.hexdigest()


def _strip_url_credentials(url: str) -> str:
    """Remove embedded credentials and query params from a git remote URL."""
    try:
        parsed = urlparse(url)
        needs_clean = False
        clean_netloc = parsed.netloc
        if parsed.username or parsed.password:
            # Reconstruct without credentials
            clean_netloc = parsed.hostname or ""
            if parsed.port:
                clean_netloc += f":{parsed.port}"
            needs_clean = True
        # Strip query params and fragments that may contain tokens
        if parsed.query or parsed.fragment:
            needs_clean = True
        if needs_clean:
            return urlunparse(parsed._replace(
                netloc=clean_netloc, query="", fragment="",
            ))
    except Exception:
        # If URL parsing/reconstruction fails, return a safe
        # placeholder instead of the original (which may contain credentials).
        # The old code did `pass` + `return url`, leaking embedded PATs.
        return "[credential-redacted-url]"
    return url


def _now_rfc3339() -> str:
    """Current time in RFC 3339 format."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def get_repo_root(cwd: Optional[str] = None) -> str:
    """Get the git repository root."""
    return _run_git(["rev-parse", "--show-toplevel"], cwd=cwd).strip()


def _normalize_for_detection(text: str) -> str:
    """Normalize text for AI signal detection.

    Strips invisible/formatting characters, resolves Unicode homoglyphs,
    and removes combining marks to produce a canonical ASCII-ish string
    suitable for substring matching against known AI signals.

    Order: strip Cf → NFKC → confusable map → strip Mn/Me.
    """
    # Strip Cf (format chars: ZWJ, ZWNJ, ZWSP, variation selectors)
    # before NFKC to prevent zero-width insertion from affecting normalization.
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    # NFKC collapses compatibility variants (e.g., fullwidth Ｃ→C)
    text = unicodedata.normalize("NFKC", text)
    # Normalize Unicode dash/hyphen variants to ASCII '-'
    text = "".join(_DASH_TO_ASCII.get(c, c) for c in text)
    # Resolve cross-script homoglyphs that NFKC doesn't cover
    text = "".join(_CONFUSABLE_TO_ASCII.get(c, c) for c in text)
    # Strip combining marks (Mn) and enclosing marks (Me) — variation
    # selectors and diacriticals that survive NFKC
    text = "".join(
        c for c in text if unicodedata.category(c) not in ("Mn", "Me")
    )
    return text
