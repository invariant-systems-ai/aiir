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
from aiir import __version__ as CLI_VERSION  # noqa: E402, F401  # re-exported

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
    "ok": ("\u2705", "[ok]"),  # ✅
    "error": ("\u274c", "[error]"),  # ❌
    "hint": ("\U0001f4a1", "[hint]"),  # 💡
    "ai": ("\U0001f916", "[AI]"),  # 🤖
    "signed": ("\U0001f58a\ufe0f", "[signed]"),  # 🖊️
    "tip": ("\U0001f4dd", "[tip]"),  # 📝
    "shrug": ("\U0001f937", "[info]"),  # 🤷
    "check": ("\u2714", "ok"),  # ✔
}

# Box-drawing glyphs used in format_receipt_pretty.  These survive on cp437
# (DOS/Windows Console Host) but crash on cp1252 (PowerShell default),
# latin-1, and ASCII.  Fall back to safe ASCII art (+, -, |).
_BOX: Dict[str, Tuple[str, str]] = {
    "tl": ("\u250c", "+"),  # ┌  top-left corner
    "vl": ("\u2502", "|"),  # │  vertical line
    "bl": ("\u2514", "+"),  # └  bottom-left corner
    "hl": ("\u2500", "-"),  # ─  horizontal line
}


def _can_encode(probe: str) -> bool:
    """Return True if stderr can encode *probe* without error."""
    try:
        enc = getattr(sys.stderr, "encoding", None) or "ascii"
        probe.encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):  # pragma: no cover
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


# Unicode TR39 confusable map — characters that NFKC does NOT resolve.
# Source: Unicode Security Mechanisms for UTS #39, confusables.txt
# URL: https://www.unicode.org/Public/security/latest/confusables.txt
# Version: 17.0.0 (2025-07-22)
# Scope: 669 single-codepoint → ASCII letter/digit mappings across
#         69 scripts (Cyrillic, Greek, Armenian, Cherokee, Coptic,
#         Lisu, Warang Citi, Mathematical, and 61+ others).
# Generation: Programmatically extracted — see scripts/gen_confusables.py.
# Only entries where NFKC(source) ≠ target are included.
_CONFUSABLE_TO_ASCII = {
    "\u00d7": "x",  # MULTIPLICATION SIGN
    "\u00fe": "p",  # LATIN SMALL LETTER THORN
    "\u0131": "i",  # LATIN SMALL LETTER DOTLESS I
    "\u017f": "f",  # LATIN SMALL LETTER LONG S
    "\u0184": "b",  # LATIN CAPITAL LETTER TONE SIX
    "\u018d": "g",  # LATIN SMALL LETTER TURNED DELTA
    "\u0192": "f",  # LATIN SMALL LETTER F WITH HOOK
    "\u0196": "l",  # LATIN CAPITAL LETTER IOTA
    "\u01a6": "R",  # LATIN LETTER YR
    "\u01a7": "2",  # LATIN CAPITAL LETTER TONE TWO
    "\u01b7": "3",  # LATIN CAPITAL LETTER EZH
    "\u01bc": "5",  # LATIN CAPITAL LETTER TONE FIVE
    "\u01bd": "s",  # LATIN SMALL LETTER TONE FIVE
    "\u01bf": "p",  # LATIN LETTER WYNN
    "\u01c0": "l",  # LATIN LETTER DENTAL CLICK
    "\u021c": "3",  # LATIN CAPITAL LETTER YOGH
    "\u0222": "8",  # LATIN CAPITAL LETTER OU
    "\u0223": "8",  # LATIN SMALL LETTER OU
    "\u0251": "a",  # LATIN SMALL LETTER ALPHA
    "\u0261": "g",  # LATIN SMALL LETTER SCRIPT G
    "\u0263": "y",  # LATIN SMALL LETTER GAMMA
    "\u0269": "i",  # LATIN SMALL LETTER IOTA
    "\u026a": "i",  # LATIN LETTER SMALL CAPITAL I
    "\u026f": "w",  # LATIN SMALL LETTER TURNED M
    "\u028b": "u",  # LATIN SMALL LETTER V WITH HOOK
    "\u028f": "y",  # LATIN LETTER SMALL CAPITAL Y
    "\u02db": "i",  # OGONEK
    "\u037a": "i",  # GREEK YPOGEGRAMMENI
    "\u037f": "J",  # GREEK CAPITAL LETTER YOT
    "\u0391": "A",  # GREEK CAPITAL LETTER ALPHA
    "\u0392": "B",  # GREEK CAPITAL LETTER BETA
    "\u0395": "E",  # GREEK CAPITAL LETTER EPSILON
    "\u0396": "Z",  # GREEK CAPITAL LETTER ZETA
    "\u0397": "H",  # GREEK CAPITAL LETTER ETA
    "\u0399": "l",  # GREEK CAPITAL LETTER IOTA
    "\u039a": "K",  # GREEK CAPITAL LETTER KAPPA
    "\u039c": "M",  # GREEK CAPITAL LETTER MU
    "\u039d": "N",  # GREEK CAPITAL LETTER NU
    "\u039f": "O",  # GREEK CAPITAL LETTER OMICRON
    "\u03a1": "P",  # GREEK CAPITAL LETTER RHO
    "\u03a4": "T",  # GREEK CAPITAL LETTER TAU
    "\u03a5": "Y",  # GREEK CAPITAL LETTER UPSILON
    "\u03a7": "X",  # GREEK CAPITAL LETTER CHI
    "\u03b1": "a",  # GREEK SMALL LETTER ALPHA
    "\u03b3": "y",  # GREEK SMALL LETTER GAMMA
    "\u03b9": "i",  # GREEK SMALL LETTER IOTA
    "\u03bd": "v",  # GREEK SMALL LETTER NU
    "\u03bf": "o",  # GREEK SMALL LETTER OMICRON
    "\u03c1": "p",  # GREEK SMALL LETTER RHO
    "\u03c3": "o",  # GREEK SMALL LETTER SIGMA
    "\u03c5": "u",  # GREEK SMALL LETTER UPSILON
    "\u03d2": "Y",  # GREEK UPSILON WITH HOOK SYMBOL
    "\u03dc": "F",  # GREEK LETTER DIGAMMA
    "\u03e8": "2",  # COPTIC CAPITAL LETTER HORI
    "\u03ec": "6",  # COPTIC CAPITAL LETTER SHIMA
    "\u03ed": "o",  # COPTIC SMALL LETTER SHIMA
    "\u03f1": "p",  # GREEK RHO SYMBOL
    "\u03f2": "c",  # GREEK LUNATE SIGMA SYMBOL
    "\u03f3": "j",  # GREEK LETTER YOT
    "\u03f8": "p",  # GREEK SMALL LETTER SHO
    "\u03f9": "C",  # GREEK CAPITAL LUNATE SIGMA SYMBOL
    "\u03fa": "M",  # GREEK CAPITAL LETTER SAN
    "\u0405": "S",  # CYRILLIC CAPITAL LETTER DZE
    "\u0406": "l",  # CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
    "\u0408": "J",  # CYRILLIC CAPITAL LETTER JE
    "\u0410": "A",  # CYRILLIC CAPITAL LETTER A
    "\u0412": "B",  # CYRILLIC CAPITAL LETTER VE
    "\u0415": "E",  # CYRILLIC CAPITAL LETTER IE
    "\u0417": "3",  # CYRILLIC CAPITAL LETTER ZE
    "\u041a": "K",  # CYRILLIC CAPITAL LETTER KA
    "\u041c": "M",  # CYRILLIC CAPITAL LETTER EM
    "\u041d": "H",  # CYRILLIC CAPITAL LETTER EN
    "\u041e": "O",  # CYRILLIC CAPITAL LETTER O
    "\u0420": "P",  # CYRILLIC CAPITAL LETTER ER
    "\u0421": "C",  # CYRILLIC CAPITAL LETTER ES
    "\u0422": "T",  # CYRILLIC CAPITAL LETTER TE
    "\u0423": "Y",  # CYRILLIC CAPITAL LETTER U
    "\u0425": "X",  # CYRILLIC CAPITAL LETTER HA
    "\u042c": "b",  # CYRILLIC CAPITAL LETTER SOFT SIGN
    "\u0430": "a",  # CYRILLIC SMALL LETTER A
    "\u0431": "6",  # CYRILLIC SMALL LETTER BE
    "\u0433": "r",  # CYRILLIC SMALL LETTER GHE
    "\u0435": "e",  # CYRILLIC SMALL LETTER IE
    "\u043e": "o",  # CYRILLIC SMALL LETTER O
    "\u0440": "p",  # CYRILLIC SMALL LETTER ER
    "\u0441": "c",  # CYRILLIC SMALL LETTER ES
    "\u0443": "y",  # CYRILLIC SMALL LETTER U
    "\u0445": "x",  # CYRILLIC SMALL LETTER HA
    "\u0448": "w",  # CYRILLIC SMALL LETTER SHA
    "\u0455": "s",  # CYRILLIC SMALL LETTER DZE
    "\u0456": "i",  # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "\u0458": "j",  # CYRILLIC SMALL LETTER JE
    "\u0461": "w",  # CYRILLIC SMALL LETTER OMEGA
    "\u0474": "V",  # CYRILLIC CAPITAL LETTER IZHITSA
    "\u0475": "v",  # CYRILLIC SMALL LETTER IZHITSA
    "\u04ae": "Y",  # CYRILLIC CAPITAL LETTER STRAIGHT U
    "\u04af": "y",  # CYRILLIC SMALL LETTER STRAIGHT U
    "\u04bb": "h",  # CYRILLIC SMALL LETTER SHHA
    "\u04bd": "e",  # CYRILLIC SMALL LETTER ABKHASIAN CHE
    "\u04c0": "l",  # CYRILLIC LETTER PALOCHKA
    "\u04cf": "l",  # CYRILLIC SMALL LETTER PALOCHKA
    "\u04e0": "3",  # CYRILLIC CAPITAL LETTER ABKHASIAN DZE
    "\u0501": "d",  # CYRILLIC SMALL LETTER KOMI DE
    "\u050c": "G",  # CYRILLIC CAPITAL LETTER KOMI SJE
    "\u051b": "q",  # CYRILLIC SMALL LETTER QA
    "\u051c": "W",  # CYRILLIC CAPITAL LETTER WE
    "\u051d": "w",  # CYRILLIC SMALL LETTER WE
    "\u054d": "U",  # ARMENIAN CAPITAL LETTER SEH
    "\u054f": "S",  # ARMENIAN CAPITAL LETTER TIWN
    "\u0555": "O",  # ARMENIAN CAPITAL LETTER OH
    "\u0561": "w",  # ARMENIAN SMALL LETTER AYB
    "\u0563": "q",  # ARMENIAN SMALL LETTER GIM
    "\u0566": "q",  # ARMENIAN SMALL LETTER ZA
    "\u0570": "h",  # ARMENIAN SMALL LETTER HO
    "\u0578": "n",  # ARMENIAN SMALL LETTER VO
    "\u057c": "n",  # ARMENIAN SMALL LETTER RA
    "\u057d": "u",  # ARMENIAN SMALL LETTER SEH
    "\u0581": "g",  # ARMENIAN SMALL LETTER CO
    "\u0582": "i",  # ARMENIAN SMALL LETTER YIWN
    "\u0584": "f",  # ARMENIAN SMALL LETTER KEH
    "\u0585": "o",  # ARMENIAN SMALL LETTER OH
    "\u05c0": "l",  # HEBREW PUNCTUATION PASEQ
    "\u05d5": "l",  # HEBREW LETTER VAV
    "\u05d8": "v",  # HEBREW LETTER TET
    "\u05df": "l",  # HEBREW LETTER FINAL NUN
    "\u05e1": "o",  # HEBREW LETTER SAMEKH
    "\u0627": "l",  # ARABIC LETTER ALEF
    "\u0647": "o",  # ARABIC LETTER HEH
    "\u0661": "l",  # ARABIC-INDIC DIGIT ONE
    "\u0665": "o",  # ARABIC-INDIC DIGIT FIVE
    "\u0667": "V",  # ARABIC-INDIC DIGIT SEVEN
    "\u06be": "o",  # ARABIC LETTER HEH DOACHASHMEE
    "\u06c1": "o",  # ARABIC LETTER HEH GOAL
    "\u06d5": "o",  # ARABIC LETTER AE
    "\u06f1": "l",  # EXTENDED ARABIC-INDIC DIGIT ONE
    "\u06f5": "o",  # EXTENDED ARABIC-INDIC DIGIT FIVE
    "\u06f7": "V",  # EXTENDED ARABIC-INDIC DIGIT SEVEN
    "\u07c0": "O",  # NKO DIGIT ZERO
    "\u07ca": "l",  # NKO LETTER A
    "\u0966": "o",  # DEVANAGARI DIGIT ZERO
    "\u0969": "3",  # DEVANAGARI DIGIT THREE
    "\u09e6": "o",  # BENGALI DIGIT ZERO
    "\u09ea": "8",  # BENGALI DIGIT FOUR
    "\u09ed": "9",  # BENGALI DIGIT SEVEN
    "\u0a66": "o",  # GURMUKHI DIGIT ZERO
    "\u0a67": "9",  # GURMUKHI DIGIT ONE
    "\u0a6a": "8",  # GURMUKHI DIGIT FOUR
    "\u0ae6": "o",  # GUJARATI DIGIT ZERO
    "\u0ae9": "3",  # GUJARATI DIGIT THREE
    "\u0b03": "8",  # ORIYA SIGN VISARGA
    "\u0b20": "O",  # ORIYA LETTER TTHA
    "\u0b66": "o",  # ORIYA DIGIT ZERO
    "\u0b68": "9",  # ORIYA DIGIT TWO
    "\u0be6": "o",  # TAMIL DIGIT ZERO
    "\u0c02": "o",  # TELUGU SIGN ANUSVARA
    "\u0c66": "o",  # TELUGU DIGIT ZERO
    "\u0c82": "o",  # KANNADA SIGN ANUSVARA
    "\u0ce6": "O",  # KANNADA DIGIT ZERO
    "\u0d02": "o",  # MALAYALAM SIGN ANUSVARA
    "\u0d1f": "s",  # MALAYALAM LETTER TTA
    "\u0d20": "o",  # MALAYALAM LETTER TTHA
    "\u0d66": "o",  # MALAYALAM DIGIT ZERO
    "\u0d6d": "9",  # MALAYALAM DIGIT SEVEN
    "\u0d82": "o",  # SINHALA SIGN ANUSVARAYA
    "\u0e50": "o",  # THAI DIGIT ZERO
    "\u0ed0": "o",  # LAO DIGIT ZERO
    "\u1004": "c",  # MYANMAR LETTER NGA
    "\u101d": "o",  # MYANMAR LETTER WA
    "\u1040": "o",  # MYANMAR DIGIT ZERO
    "\u105a": "c",  # MYANMAR LETTER MON NGA
    "\u10e7": "y",  # GEORGIAN LETTER QAR
    "\u10ff": "o",  # GEORGIAN LETTER LABIAL SIGN
    "\u1200": "U",  # ETHIOPIC SYLLABLE HA
    "\u12d0": "O",  # ETHIOPIC SYLLABLE PHARYNGEAL A
    "\u13a0": "D",  # CHEROKEE LETTER A
    "\u13a1": "R",  # CHEROKEE LETTER E
    "\u13a2": "T",  # CHEROKEE LETTER I
    "\u13a5": "i",  # CHEROKEE LETTER V
    "\u13a9": "Y",  # CHEROKEE LETTER GI
    "\u13aa": "A",  # CHEROKEE LETTER GO
    "\u13ab": "J",  # CHEROKEE LETTER GU
    "\u13ac": "E",  # CHEROKEE LETTER GV
    "\u13b3": "W",  # CHEROKEE LETTER LA
    "\u13b7": "M",  # CHEROKEE LETTER LU
    "\u13bb": "H",  # CHEROKEE LETTER MI
    "\u13bd": "Y",  # CHEROKEE LETTER MU
    "\u13c0": "G",  # CHEROKEE LETTER NAH
    "\u13c2": "h",  # CHEROKEE LETTER NI
    "\u13c3": "Z",  # CHEROKEE LETTER NO
    "\u13ce": "4",  # CHEROKEE LETTER SE
    "\u13cf": "b",  # CHEROKEE LETTER SI
    "\u13d2": "R",  # CHEROKEE LETTER SV
    "\u13d4": "W",  # CHEROKEE LETTER TA
    "\u13d5": "S",  # CHEROKEE LETTER DE
    "\u13d9": "V",  # CHEROKEE LETTER DO
    "\u13da": "S",  # CHEROKEE LETTER DU
    "\u13de": "L",  # CHEROKEE LETTER TLE
    "\u13df": "C",  # CHEROKEE LETTER TLI
    "\u13e2": "P",  # CHEROKEE LETTER TLV
    "\u13e6": "K",  # CHEROKEE LETTER TSO
    "\u13e7": "d",  # CHEROKEE LETTER TSU
    "\u13ee": "6",  # CHEROKEE LETTER WV
    "\u13f3": "G",  # CHEROKEE LETTER YU
    "\u13f4": "B",  # CHEROKEE LETTER YV
    "\u142f": "V",  # CANADIAN SYLLABICS PE
    "\u144c": "U",  # CANADIAN SYLLABICS TE
    "\u146d": "P",  # CANADIAN SYLLABICS KI
    "\u146f": "d",  # CANADIAN SYLLABICS KO
    "\u1472": "b",  # CANADIAN SYLLABICS KA
    "\u148d": "J",  # CANADIAN SYLLABICS CO
    "\u14aa": "L",  # CANADIAN SYLLABICS MA
    "\u14bf": "2",  # CANADIAN SYLLABICS SAYISI M
    "\u1541": "x",  # CANADIAN SYLLABICS SAYISI YI
    "\u157c": "H",  # CANADIAN SYLLABICS NUNAVUT H
    "\u157d": "x",  # CANADIAN SYLLABICS HK
    "\u1587": "R",  # CANADIAN SYLLABICS TLHI
    "\u15af": "b",  # CANADIAN SYLLABICS AIVILIK B
    "\u15b4": "F",  # CANADIAN SYLLABICS BLACKFOOT WE
    "\u15c5": "A",  # CANADIAN SYLLABICS CARRIER GHO
    "\u15de": "D",  # CANADIAN SYLLABICS CARRIER THE
    "\u15ea": "D",  # CANADIAN SYLLABICS CARRIER PE
    "\u15f0": "M",  # CANADIAN SYLLABICS CARRIER GO
    "\u15f7": "B",  # CANADIAN SYLLABICS CARRIER KHE
    "\u166d": "X",  # CANADIAN SYLLABICS CHI SIGN
    "\u166e": "x",  # CANADIAN SYLLABICS FULL STOP
    "\u16b7": "X",  # RUNIC LETTER GEBO GYFU G
    "\u16c1": "l",  # RUNIC LETTER ISAZ IS ISS I
    "\u16d5": "K",  # RUNIC LETTER OPEN-P
    "\u16d6": "M",  # RUNIC LETTER EHWAZ EH E
    "\u17e0": "o",  # KHMER DIGIT ZERO
    "\u1d04": "c",  # LATIN LETTER SMALL CAPITAL C
    "\u1d0f": "o",  # LATIN LETTER SMALL CAPITAL O
    "\u1d11": "o",  # LATIN SMALL LETTER SIDEWAYS O
    "\u1d1c": "u",  # LATIN LETTER SMALL CAPITAL U
    "\u1d20": "v",  # LATIN LETTER SMALL CAPITAL V
    "\u1d21": "w",  # LATIN LETTER SMALL CAPITAL W
    "\u1d22": "z",  # LATIN LETTER SMALL CAPITAL Z
    "\u1d26": "r",  # GREEK LETTER SMALL CAPITAL GAMMA
    "\u1d83": "g",  # LATIN SMALL LETTER G WITH PALATAL HOOK
    "\u1d8c": "y",  # LATIN SMALL LETTER V WITH PALATAL HOOK
    "\u1e9d": "f",  # LATIN SMALL LETTER LONG S WITH HIGH STROKE
    "\u1eff": "y",  # LATIN SMALL LETTER Y WITH LOOP
    "\u1fbe": "i",  # GREEK PROSGEGRAMMENI
    "\u2110": "l",  # SCRIPT CAPITAL I
    "\u2111": "l",  # BLACK-LETTER CAPITAL I
    "\u212e": "e",  # ESTIMATED SYMBOL
    "\u213d": "y",  # DOUBLE-STRUCK SMALL GAMMA
    "\u2160": "l",  # ROMAN NUMERAL ONE
    "\u2223": "l",  # DIVIDES
    "\u2228": "v",  # LOGICAL OR
    "\u222a": "U",  # UNION
    "\u22a4": "T",  # DOWN TACK
    "\u22c1": "v",  # N-ARY LOGICAL OR
    "\u22c3": "U",  # N-ARY UNION
    "\u22ff": "E",  # Z NOTATION BAG MEMBERSHIP
    "\u2373": "i",  # APL FUNCTIONAL SYMBOL IOTA
    "\u2374": "p",  # APL FUNCTIONAL SYMBOL RHO
    "\u237a": "a",  # APL FUNCTIONAL SYMBOL ALPHA
    "\u23fd": "l",  # POWER ON SYMBOL
    "\u2573": "X",  # BOX DRAWINGS LIGHT DIAGONAL CROSS
    "\u27d9": "T",  # LARGE DOWN TACK
    "\u292b": "x",  # RISING DIAGONAL CROSSING FALLING DIAGONAL
    "\u292c": "x",  # FALLING DIAGONAL CROSSING RISING DIAGONAL
    "\u2a2f": "x",  # VECTOR OR CROSS PRODUCT
    "\u2c82": "B",  # COPTIC CAPITAL LETTER VIDA
    "\u2c85": "r",  # COPTIC SMALL LETTER GAMMA
    "\u2c8e": "H",  # COPTIC CAPITAL LETTER HATE
    "\u2c92": "l",  # COPTIC CAPITAL LETTER IAUDA
    "\u2c93": "i",  # COPTIC SMALL LETTER IAUDA
    "\u2c94": "K",  # COPTIC CAPITAL LETTER KAPA
    "\u2c98": "M",  # COPTIC CAPITAL LETTER MI
    "\u2c9a": "N",  # COPTIC CAPITAL LETTER NI
    "\u2c9c": "3",  # COPTIC CAPITAL LETTER KSI
    "\u2c9e": "O",  # COPTIC CAPITAL LETTER O
    "\u2c9f": "o",  # COPTIC SMALL LETTER O
    "\u2ca2": "P",  # COPTIC CAPITAL LETTER RO
    "\u2ca3": "p",  # COPTIC SMALL LETTER RO
    "\u2ca4": "C",  # COPTIC CAPITAL LETTER SIMA
    "\u2ca5": "c",  # COPTIC SMALL LETTER SIMA
    "\u2ca6": "T",  # COPTIC CAPITAL LETTER TAU
    "\u2ca8": "Y",  # COPTIC CAPITAL LETTER UA
    "\u2ca9": "y",  # COPTIC SMALL LETTER UA
    "\u2cac": "X",  # COPTIC CAPITAL LETTER KHI
    "\u2cbd": "w",  # COPTIC SMALL LETTER CRYPTOGRAMMIC NI
    "\u2cc4": "3",  # COPTIC CAPITAL LETTER OLD COPTIC SHEI
    "\u2cca": "9",  # COPTIC CAPITAL LETTER DIALECT-P HORI
    "\u2ccb": "9",  # COPTIC SMALL LETTER DIALECT-P HORI
    "\u2ccc": "3",  # COPTIC CAPITAL LETTER OLD COPTIC HORI
    "\u2cce": "P",  # COPTIC CAPITAL LETTER OLD COPTIC HA
    "\u2ccf": "p",  # COPTIC SMALL LETTER OLD COPTIC HA
    "\u2cd0": "L",  # COPTIC CAPITAL LETTER L-SHAPED HA
    "\u2cd2": "6",  # COPTIC CAPITAL LETTER OLD COPTIC HEI
    "\u2cd3": "6",  # COPTIC SMALL LETTER OLD COPTIC HEI
    "\u2cdc": "6",  # COPTIC CAPITAL LETTER OLD NUBIAN SHIMA
    "\u2d38": "V",  # TIFINAGH LETTER YADH
    "\u2d39": "E",  # TIFINAGH LETTER YADD
    "\u2d4f": "l",  # TIFINAGH LETTER YAN
    "\u2d54": "O",  # TIFINAGH LETTER YAR
    "\u2d55": "Q",  # TIFINAGH LETTER YARR
    "\u2d5d": "X",  # TIFINAGH LETTER YATH
    "\u3007": "O",  # IDEOGRAPHIC NUMBER ZERO
    "\ua4d0": "B",  # LISU LETTER BA
    "\ua4d1": "P",  # LISU LETTER PA
    "\ua4d2": "d",  # LISU LETTER PHA
    "\ua4d3": "D",  # LISU LETTER DA
    "\ua4d4": "T",  # LISU LETTER TA
    "\ua4d6": "G",  # LISU LETTER GA
    "\ua4d7": "K",  # LISU LETTER KA
    "\ua4d9": "J",  # LISU LETTER JA
    "\ua4da": "C",  # LISU LETTER CA
    "\ua4dc": "Z",  # LISU LETTER DZA
    "\ua4dd": "F",  # LISU LETTER TSA
    "\ua4df": "M",  # LISU LETTER MA
    "\ua4e0": "N",  # LISU LETTER NA
    "\ua4e1": "L",  # LISU LETTER LA
    "\ua4e2": "S",  # LISU LETTER SA
    "\ua4e3": "R",  # LISU LETTER ZHA
    "\ua4e6": "V",  # LISU LETTER HA
    "\ua4e7": "H",  # LISU LETTER XA
    "\ua4ea": "W",  # LISU LETTER WA
    "\ua4eb": "X",  # LISU LETTER SHA
    "\ua4ec": "Y",  # LISU LETTER YA
    "\ua4ee": "A",  # LISU LETTER A
    "\ua4f0": "E",  # LISU LETTER E
    "\ua4f2": "l",  # LISU LETTER I
    "\ua4f3": "O",  # LISU LETTER O
    "\ua4f4": "U",  # LISU LETTER U
    "\ua644": "2",  # CYRILLIC CAPITAL LETTER REVERSED DZE
    "\ua647": "i",  # CYRILLIC SMALL LETTER IOTA
    "\ua6df": "V",  # BAMUM LETTER KO
    "\ua6ef": "2",  # BAMUM LETTER KOGHOM
    "\ua731": "s",  # LATIN LETTER SMALL CAPITAL S
    "\ua75a": "2",  # LATIN CAPITAL LETTER R ROTUNDA
    "\ua76a": "3",  # LATIN CAPITAL LETTER ET
    "\ua76e": "9",  # LATIN CAPITAL LETTER CON
    "\ua798": "F",  # LATIN CAPITAL LETTER F WITH STROKE
    "\ua799": "f",  # LATIN SMALL LETTER F WITH STROKE
    "\ua79f": "u",  # LATIN SMALL LETTER VOLAPUK UE
    "\ua7ab": "3",  # LATIN CAPITAL LETTER REVERSED OPEN E
    "\ua7b2": "J",  # LATIN CAPITAL LETTER J WITH CROSSED-TAIL
    "\ua7b3": "X",  # LATIN CAPITAL LETTER CHI
    "\ua7b4": "B",  # LATIN CAPITAL LETTER BETA
    "\uab32": "e",  # LATIN SMALL LETTER BLACKLETTER E
    "\uab35": "f",  # LATIN SMALL LETTER LENIS F
    "\uab3d": "o",  # LATIN SMALL LETTER BLACKLETTER O
    "\uab47": "r",  # LATIN SMALL LETTER R WITHOUT HANDLE
    "\uab48": "r",  # LATIN SMALL LETTER DOUBLE R
    "\uab4e": "u",  # LATIN SMALL LETTER U WITH SHORT RIGHT LEG
    "\uab52": "u",  # LATIN SMALL LETTER U WITH LEFT HOOK
    "\uab5a": "y",  # LATIN SMALL LETTER Y WITH SHORT RIGHT LEG
    "\uab75": "i",  # CHEROKEE SMALL LETTER V
    "\uab81": "r",  # CHEROKEE SMALL LETTER HU
    "\uab83": "w",  # CHEROKEE SMALL LETTER LA
    "\uab93": "z",  # CHEROKEE SMALL LETTER NO
    "\uaba9": "v",  # CHEROKEE SMALL LETTER DO
    "\uabaa": "s",  # CHEROKEE SMALL LETTER DU
    "\uabaf": "c",  # CHEROKEE SMALL LETTER TLI
    "\ufba6": "o",  # ARABIC LETTER HEH GOAL ISOLATED FORM
    "\ufba7": "o",  # ARABIC LETTER HEH GOAL FINAL FORM
    "\ufba8": "o",  # ARABIC LETTER HEH GOAL INITIAL FORM
    "\ufba9": "o",  # ARABIC LETTER HEH GOAL MEDIAL FORM
    "\ufbaa": "o",  # ARABIC LETTER HEH DOACHASHMEE ISOLATED FORM
    "\ufbab": "o",  # ARABIC LETTER HEH DOACHASHMEE FINAL FORM
    "\ufbac": "o",  # ARABIC LETTER HEH DOACHASHMEE INITIAL FORM
    "\ufbad": "o",  # ARABIC LETTER HEH DOACHASHMEE MEDIAL FORM
    "\ufe8d": "l",  # ARABIC LETTER ALEF ISOLATED FORM
    "\ufe8e": "l",  # ARABIC LETTER ALEF FINAL FORM
    "\ufee9": "o",  # ARABIC LETTER HEH ISOLATED FORM
    "\ufeea": "o",  # ARABIC LETTER HEH FINAL FORM
    "\ufeeb": "o",  # ARABIC LETTER HEH INITIAL FORM
    "\ufeec": "o",  # ARABIC LETTER HEH MEDIAL FORM
    "\uff29": "l",  # FULLWIDTH LATIN CAPITAL LETTER I
    "\uffe8": "l",  # HALFWIDTH FORMS LIGHT VERTICAL
    "\U00010282": "B",  # LYCIAN LETTER B
    "\U00010286": "E",  # LYCIAN LETTER I
    "\U00010287": "F",  # LYCIAN LETTER W
    "\U0001028a": "l",  # LYCIAN LETTER J
    "\U00010290": "X",  # LYCIAN LETTER MM
    "\U00010292": "O",  # LYCIAN LETTER U
    "\U00010295": "P",  # LYCIAN LETTER R
    "\U00010296": "S",  # LYCIAN LETTER S
    "\U00010297": "T",  # LYCIAN LETTER T
    "\U000102a0": "A",  # CARIAN LETTER A
    "\U000102a1": "B",  # CARIAN LETTER P2
    "\U000102a2": "C",  # CARIAN LETTER D
    "\U000102a5": "F",  # CARIAN LETTER R
    "\U000102ab": "O",  # CARIAN LETTER O
    "\U000102b0": "M",  # CARIAN LETTER S
    "\U000102b1": "T",  # CARIAN LETTER C-18
    "\U000102b2": "Y",  # CARIAN LETTER U
    "\U000102b4": "X",  # CARIAN LETTER X
    "\U000102cf": "H",  # CARIAN LETTER E2
    "\U000102f5": "Z",  # COPTIC EPACT NUMBER THREE HUNDRED
    "\U00010301": "B",  # OLD ITALIC LETTER BE
    "\U00010302": "C",  # OLD ITALIC LETTER KE
    "\U00010309": "l",  # OLD ITALIC LETTER I
    "\U00010311": "M",  # OLD ITALIC LETTER SHE
    "\U00010315": "T",  # OLD ITALIC LETTER TE
    "\U00010317": "X",  # OLD ITALIC LETTER EKS
    "\U0001031a": "8",  # OLD ITALIC LETTER EF
    "\U00010320": "l",  # OLD ITALIC NUMERAL ONE
    "\U00010322": "X",  # OLD ITALIC NUMERAL TEN
    "\U00010404": "O",  # DESERET CAPITAL LETTER LONG O
    "\U00010415": "C",  # DESERET CAPITAL LETTER CHEE
    "\U0001041b": "L",  # DESERET CAPITAL LETTER ETH
    "\U00010420": "S",  # DESERET CAPITAL LETTER ZHEE
    "\U0001042c": "o",  # DESERET SMALL LETTER LONG O
    "\U0001043d": "c",  # DESERET SMALL LETTER CHEE
    "\U00010448": "s",  # DESERET SMALL LETTER ZHEE
    "\U000104b4": "R",  # OSAGE CAPITAL LETTER BRA
    "\U000104c2": "O",  # OSAGE CAPITAL LETTER O
    "\U000104ce": "U",  # OSAGE CAPITAL LETTER U
    "\U000104d2": "7",  # OSAGE CAPITAL LETTER ZA
    "\U000104ea": "o",  # OSAGE SMALL LETTER O
    "\U000104f6": "u",  # OSAGE SMALL LETTER U
    "\U00010513": "N",  # ELBASAN LETTER NE
    "\U00010516": "O",  # ELBASAN LETTER O
    "\U00010518": "K",  # ELBASAN LETTER QE
    "\U0001051c": "C",  # ELBASAN LETTER SHE
    "\U0001051d": "V",  # ELBASAN LETTER TE
    "\U00010525": "F",  # ELBASAN LETTER GHE
    "\U00010526": "L",  # ELBASAN LETTER GHAMMA
    "\U00010527": "X",  # ELBASAN LETTER KHE
    "\U000114d0": "o",  # TIRHUTA DIGIT ZERO
    "\U00011706": "v",  # AHOM LETTER PA
    "\U0001170a": "w",  # AHOM LETTER JA
    "\U0001170e": "w",  # AHOM LETTER LA
    "\U0001170f": "w",  # AHOM LETTER SA
    "\U000118a0": "V",  # WARANG CITI CAPITAL LETTER NGAA
    "\U000118a2": "F",  # WARANG CITI CAPITAL LETTER WI
    "\U000118a3": "L",  # WARANG CITI CAPITAL LETTER YU
    "\U000118a4": "Y",  # WARANG CITI CAPITAL LETTER YA
    "\U000118a6": "E",  # WARANG CITI CAPITAL LETTER II
    "\U000118a9": "Z",  # WARANG CITI CAPITAL LETTER O
    "\U000118ac": "9",  # WARANG CITI CAPITAL LETTER KO
    "\U000118ae": "E",  # WARANG CITI CAPITAL LETTER YUJ
    "\U000118af": "4",  # WARANG CITI CAPITAL LETTER UC
    "\U000118b2": "L",  # WARANG CITI CAPITAL LETTER TTE
    "\U000118b5": "O",  # WARANG CITI CAPITAL LETTER AT
    "\U000118b8": "U",  # WARANG CITI CAPITAL LETTER PU
    "\U000118bb": "5",  # WARANG CITI CAPITAL LETTER HORR
    "\U000118bc": "T",  # WARANG CITI CAPITAL LETTER HAR
    "\U000118c0": "v",  # WARANG CITI SMALL LETTER NGAA
    "\U000118c1": "s",  # WARANG CITI SMALL LETTER A
    "\U000118c2": "F",  # WARANG CITI SMALL LETTER WI
    "\U000118c3": "i",  # WARANG CITI SMALL LETTER YU
    "\U000118c4": "z",  # WARANG CITI SMALL LETTER YA
    "\U000118c6": "7",  # WARANG CITI SMALL LETTER II
    "\U000118c8": "o",  # WARANG CITI SMALL LETTER E
    "\U000118ca": "3",  # WARANG CITI SMALL LETTER ANG
    "\U000118cc": "9",  # WARANG CITI SMALL LETTER KO
    "\U000118d5": "6",  # WARANG CITI SMALL LETTER AT
    "\U000118d6": "9",  # WARANG CITI SMALL LETTER AM
    "\U000118d7": "o",  # WARANG CITI SMALL LETTER BU
    "\U000118d8": "u",  # WARANG CITI SMALL LETTER PU
    "\U000118dc": "y",  # WARANG CITI SMALL LETTER HAR
    "\U000118e0": "O",  # WARANG CITI DIGIT ZERO
    "\U000118e5": "Z",  # WARANG CITI DIGIT FIVE
    "\U000118e6": "W",  # WARANG CITI DIGIT SIX
    "\U000118e9": "C",  # WARANG CITI DIGIT NINE
    "\U000118ec": "X",  # WARANG CITI NUMBER THIRTY
    "\U000118ef": "W",  # WARANG CITI NUMBER SIXTY
    "\U000118f2": "C",  # WARANG CITI NUMBER NINETY
    "\U00011dda": "l",  # UNKNOWN
    "\U00011de0": "O",  # UNKNOWN
    "\U00011de1": "l",  # UNKNOWN
    "\U00016eaa": "l",  # UNKNOWN
    "\U00016eb6": "b",  # UNKNOWN
    "\U00016f08": "V",  # MIAO LETTER VA
    "\U00016f0a": "T",  # MIAO LETTER TA
    "\U00016f16": "L",  # MIAO LETTER LA
    "\U00016f28": "l",  # MIAO LETTER GHA
    "\U00016f35": "R",  # MIAO LETTER ZHA
    "\U00016f3a": "S",  # MIAO LETTER SA
    "\U00016f3b": "3",  # MIAO LETTER ZA
    "\U00016f40": "A",  # MIAO LETTER ZZYA
    "\U00016f42": "U",  # MIAO LETTER WA
    "\U00016f43": "Y",  # MIAO LETTER AH
    "\U0001ccd6": "A",  # UNKNOWN
    "\U0001ccd7": "B",  # UNKNOWN
    "\U0001ccd8": "C",  # UNKNOWN
    "\U0001ccd9": "D",  # UNKNOWN
    "\U0001ccda": "E",  # UNKNOWN
    "\U0001ccdb": "F",  # UNKNOWN
    "\U0001ccdc": "G",  # UNKNOWN
    "\U0001ccdd": "H",  # UNKNOWN
    "\U0001ccde": "l",  # UNKNOWN
    "\U0001ccdf": "J",  # UNKNOWN
    "\U0001cce0": "K",  # UNKNOWN
    "\U0001cce1": "L",  # UNKNOWN
    "\U0001cce2": "M",  # UNKNOWN
    "\U0001cce3": "N",  # UNKNOWN
    "\U0001cce4": "O",  # UNKNOWN
    "\U0001cce5": "P",  # UNKNOWN
    "\U0001cce6": "Q",  # UNKNOWN
    "\U0001cce7": "R",  # UNKNOWN
    "\U0001cce8": "S",  # UNKNOWN
    "\U0001cce9": "T",  # UNKNOWN
    "\U0001ccea": "U",  # UNKNOWN
    "\U0001cceb": "V",  # UNKNOWN
    "\U0001ccec": "W",  # UNKNOWN
    "\U0001cced": "X",  # UNKNOWN
    "\U0001ccee": "Y",  # UNKNOWN
    "\U0001ccef": "Z",  # UNKNOWN
    "\U0001ccf0": "O",  # UNKNOWN
    "\U0001ccf1": "l",  # UNKNOWN
    "\U0001ccf2": "2",  # UNKNOWN
    "\U0001ccf3": "3",  # UNKNOWN
    "\U0001ccf4": "4",  # UNKNOWN
    "\U0001ccf5": "5",  # UNKNOWN
    "\U0001ccf6": "6",  # UNKNOWN
    "\U0001ccf7": "7",  # UNKNOWN
    "\U0001ccf8": "8",  # UNKNOWN
    "\U0001ccf9": "9",  # UNKNOWN
    "\U0001d206": "3",  # GREEK VOCAL NOTATION SYMBOL-7
    "\U0001d20d": "V",  # GREEK VOCAL NOTATION SYMBOL-14
    "\U0001d212": "7",  # GREEK VOCAL NOTATION SYMBOL-19
    "\U0001d213": "F",  # GREEK VOCAL NOTATION SYMBOL-20
    "\U0001d216": "R",  # GREEK VOCAL NOTATION SYMBOL-23
    "\U0001d22a": "L",  # GREEK INSTRUMENTAL NOTATION SYMBOL-23
    "\U0001d408": "l",  # MATHEMATICAL BOLD CAPITAL I
    "\U0001d43c": "l",  # MATHEMATICAL ITALIC CAPITAL I
    "\U0001d470": "l",  # MATHEMATICAL BOLD ITALIC CAPITAL I
    "\U0001d4d8": "l",  # MATHEMATICAL BOLD SCRIPT CAPITAL I
    "\U0001d540": "l",  # MATHEMATICAL DOUBLE-STRUCK CAPITAL I
    "\U0001d574": "l",  # MATHEMATICAL BOLD FRAKTUR CAPITAL I
    "\U0001d5a8": "l",  # MATHEMATICAL SANS-SERIF CAPITAL I
    "\U0001d5dc": "l",  # MATHEMATICAL SANS-SERIF BOLD CAPITAL I
    "\U0001d610": "l",  # MATHEMATICAL SANS-SERIF ITALIC CAPITAL I
    "\U0001d644": "l",  # MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL I
    "\U0001d678": "l",  # MATHEMATICAL MONOSPACE CAPITAL I
    "\U0001d6a4": "i",  # MATHEMATICAL ITALIC SMALL DOTLESS I
    "\U0001d6a8": "A",  # MATHEMATICAL BOLD CAPITAL ALPHA
    "\U0001d6a9": "B",  # MATHEMATICAL BOLD CAPITAL BETA
    "\U0001d6ac": "E",  # MATHEMATICAL BOLD CAPITAL EPSILON
    "\U0001d6ad": "Z",  # MATHEMATICAL BOLD CAPITAL ZETA
    "\U0001d6ae": "H",  # MATHEMATICAL BOLD CAPITAL ETA
    "\U0001d6b0": "l",  # MATHEMATICAL BOLD CAPITAL IOTA
    "\U0001d6b1": "K",  # MATHEMATICAL BOLD CAPITAL KAPPA
    "\U0001d6b3": "M",  # MATHEMATICAL BOLD CAPITAL MU
    "\U0001d6b4": "N",  # MATHEMATICAL BOLD CAPITAL NU
    "\U0001d6b6": "O",  # MATHEMATICAL BOLD CAPITAL OMICRON
    "\U0001d6b8": "P",  # MATHEMATICAL BOLD CAPITAL RHO
    "\U0001d6bb": "T",  # MATHEMATICAL BOLD CAPITAL TAU
    "\U0001d6bc": "Y",  # MATHEMATICAL BOLD CAPITAL UPSILON
    "\U0001d6be": "X",  # MATHEMATICAL BOLD CAPITAL CHI
    "\U0001d6c2": "a",  # MATHEMATICAL BOLD SMALL ALPHA
    "\U0001d6c4": "y",  # MATHEMATICAL BOLD SMALL GAMMA
    "\U0001d6ca": "i",  # MATHEMATICAL BOLD SMALL IOTA
    "\U0001d6ce": "v",  # MATHEMATICAL BOLD SMALL NU
    "\U0001d6d0": "o",  # MATHEMATICAL BOLD SMALL OMICRON
    "\U0001d6d2": "p",  # MATHEMATICAL BOLD SMALL RHO
    "\U0001d6d4": "o",  # MATHEMATICAL BOLD SMALL SIGMA
    "\U0001d6d6": "u",  # MATHEMATICAL BOLD SMALL UPSILON
    "\U0001d6e0": "p",  # MATHEMATICAL BOLD RHO SYMBOL
    "\U0001d6e2": "A",  # MATHEMATICAL ITALIC CAPITAL ALPHA
    "\U0001d6e3": "B",  # MATHEMATICAL ITALIC CAPITAL BETA
    "\U0001d6e6": "E",  # MATHEMATICAL ITALIC CAPITAL EPSILON
    "\U0001d6e7": "Z",  # MATHEMATICAL ITALIC CAPITAL ZETA
    "\U0001d6e8": "H",  # MATHEMATICAL ITALIC CAPITAL ETA
    "\U0001d6ea": "l",  # MATHEMATICAL ITALIC CAPITAL IOTA
    "\U0001d6eb": "K",  # MATHEMATICAL ITALIC CAPITAL KAPPA
    "\U0001d6ed": "M",  # MATHEMATICAL ITALIC CAPITAL MU
    "\U0001d6ee": "N",  # MATHEMATICAL ITALIC CAPITAL NU
    "\U0001d6f0": "O",  # MATHEMATICAL ITALIC CAPITAL OMICRON
    "\U0001d6f2": "P",  # MATHEMATICAL ITALIC CAPITAL RHO
    "\U0001d6f5": "T",  # MATHEMATICAL ITALIC CAPITAL TAU
    "\U0001d6f6": "Y",  # MATHEMATICAL ITALIC CAPITAL UPSILON
    "\U0001d6f8": "X",  # MATHEMATICAL ITALIC CAPITAL CHI
    "\U0001d6fc": "a",  # MATHEMATICAL ITALIC SMALL ALPHA
    "\U0001d6fe": "y",  # MATHEMATICAL ITALIC SMALL GAMMA
    "\U0001d704": "i",  # MATHEMATICAL ITALIC SMALL IOTA
    "\U0001d708": "v",  # MATHEMATICAL ITALIC SMALL NU
    "\U0001d70a": "o",  # MATHEMATICAL ITALIC SMALL OMICRON
    "\U0001d70c": "p",  # MATHEMATICAL ITALIC SMALL RHO
    "\U0001d70e": "o",  # MATHEMATICAL ITALIC SMALL SIGMA
    "\U0001d710": "u",  # MATHEMATICAL ITALIC SMALL UPSILON
    "\U0001d71a": "p",  # MATHEMATICAL ITALIC RHO SYMBOL
    "\U0001d71c": "A",  # MATHEMATICAL BOLD ITALIC CAPITAL ALPHA
    "\U0001d71d": "B",  # MATHEMATICAL BOLD ITALIC CAPITAL BETA
    "\U0001d720": "E",  # MATHEMATICAL BOLD ITALIC CAPITAL EPSILON
    "\U0001d721": "Z",  # MATHEMATICAL BOLD ITALIC CAPITAL ZETA
    "\U0001d722": "H",  # MATHEMATICAL BOLD ITALIC CAPITAL ETA
    "\U0001d724": "l",  # MATHEMATICAL BOLD ITALIC CAPITAL IOTA
    "\U0001d725": "K",  # MATHEMATICAL BOLD ITALIC CAPITAL KAPPA
    "\U0001d727": "M",  # MATHEMATICAL BOLD ITALIC CAPITAL MU
    "\U0001d728": "N",  # MATHEMATICAL BOLD ITALIC CAPITAL NU
    "\U0001d72a": "O",  # MATHEMATICAL BOLD ITALIC CAPITAL OMICRON
    "\U0001d72c": "P",  # MATHEMATICAL BOLD ITALIC CAPITAL RHO
    "\U0001d72f": "T",  # MATHEMATICAL BOLD ITALIC CAPITAL TAU
    "\U0001d730": "Y",  # MATHEMATICAL BOLD ITALIC CAPITAL UPSILON
    "\U0001d732": "X",  # MATHEMATICAL BOLD ITALIC CAPITAL CHI
    "\U0001d736": "a",  # MATHEMATICAL BOLD ITALIC SMALL ALPHA
    "\U0001d738": "y",  # MATHEMATICAL BOLD ITALIC SMALL GAMMA
    "\U0001d73e": "i",  # MATHEMATICAL BOLD ITALIC SMALL IOTA
    "\U0001d742": "v",  # MATHEMATICAL BOLD ITALIC SMALL NU
    "\U0001d744": "o",  # MATHEMATICAL BOLD ITALIC SMALL OMICRON
    "\U0001d746": "p",  # MATHEMATICAL BOLD ITALIC SMALL RHO
    "\U0001d748": "o",  # MATHEMATICAL BOLD ITALIC SMALL SIGMA
    "\U0001d74a": "u",  # MATHEMATICAL BOLD ITALIC SMALL UPSILON
    "\U0001d754": "p",  # MATHEMATICAL BOLD ITALIC RHO SYMBOL
    "\U0001d756": "A",  # MATHEMATICAL SANS-SERIF BOLD CAPITAL ALPHA
    "\U0001d757": "B",  # MATHEMATICAL SANS-SERIF BOLD CAPITAL BETA
    "\U0001d75a": "E",  # MATHEMATICAL SANS-SERIF BOLD CAPITAL EPSILON
    "\U0001d75b": "Z",  # MATHEMATICAL SANS-SERIF BOLD CAPITAL ZETA
    "\U0001d75c": "H",  # MATHEMATICAL SANS-SERIF BOLD CAPITAL ETA
    "\U0001d75e": "l",  # MATHEMATICAL SANS-SERIF BOLD CAPITAL IOTA
    "\U0001d75f": "K",  # MATHEMATICAL SANS-SERIF BOLD CAPITAL KAPPA
    "\U0001d761": "M",  # MATHEMATICAL SANS-SERIF BOLD CAPITAL MU
    "\U0001d762": "N",  # MATHEMATICAL SANS-SERIF BOLD CAPITAL NU
    "\U0001d764": "O",  # MATHEMATICAL SANS-SERIF BOLD CAPITAL OMICRON
    "\U0001d766": "P",  # MATHEMATICAL SANS-SERIF BOLD CAPITAL RHO
    "\U0001d769": "T",  # MATHEMATICAL SANS-SERIF BOLD CAPITAL TAU
    "\U0001d76a": "Y",  # MATHEMATICAL SANS-SERIF BOLD CAPITAL UPSILON
    "\U0001d76c": "X",  # MATHEMATICAL SANS-SERIF BOLD CAPITAL CHI
    "\U0001d770": "a",  # MATHEMATICAL SANS-SERIF BOLD SMALL ALPHA
    "\U0001d772": "y",  # MATHEMATICAL SANS-SERIF BOLD SMALL GAMMA
    "\U0001d778": "i",  # MATHEMATICAL SANS-SERIF BOLD SMALL IOTA
    "\U0001d77c": "v",  # MATHEMATICAL SANS-SERIF BOLD SMALL NU
    "\U0001d77e": "o",  # MATHEMATICAL SANS-SERIF BOLD SMALL OMICRON
    "\U0001d780": "p",  # MATHEMATICAL SANS-SERIF BOLD SMALL RHO
    "\U0001d782": "o",  # MATHEMATICAL SANS-SERIF BOLD SMALL SIGMA
    "\U0001d784": "u",  # MATHEMATICAL SANS-SERIF BOLD SMALL UPSILON
    "\U0001d78e": "p",  # MATHEMATICAL SANS-SERIF BOLD RHO SYMBOL
    "\U0001d790": "A",  # MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL ALPHA
    "\U0001d791": "B",  # MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL BETA
    "\U0001d794": "E",  # MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL EPSILON
    "\U0001d795": "Z",  # MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL ZETA
    "\U0001d796": "H",  # MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL ETA
    "\U0001d798": "l",  # MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL IOTA
    "\U0001d799": "K",  # MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL KAPPA
    "\U0001d79b": "M",  # MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL MU
    "\U0001d79c": "N",  # MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL NU
    "\U0001d79e": "O",  # MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL OMICRON
    "\U0001d7a0": "P",  # MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL RHO
    "\U0001d7a3": "T",  # MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL TAU
    "\U0001d7a4": "Y",  # MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL UPSILON
    "\U0001d7a6": "X",  # MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL CHI
    "\U0001d7aa": "a",  # MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL ALPHA
    "\U0001d7ac": "y",  # MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL GAMMA
    "\U0001d7b2": "i",  # MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL IOTA
    "\U0001d7b6": "v",  # MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL NU
    "\U0001d7b8": "o",  # MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL OMICRON
    "\U0001d7ba": "p",  # MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL RHO
    "\U0001d7bc": "o",  # MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL SIGMA
    "\U0001d7be": "u",  # MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL UPSILON
    "\U0001d7c8": "p",  # MATHEMATICAL SANS-SERIF BOLD ITALIC RHO SYMBOL
    "\U0001d7ca": "F",  # MATHEMATICAL BOLD CAPITAL DIGAMMA
    "\U0001d7ce": "O",  # MATHEMATICAL BOLD DIGIT ZERO
    "\U0001d7cf": "l",  # MATHEMATICAL BOLD DIGIT ONE
    "\U0001d7d8": "O",  # MATHEMATICAL DOUBLE-STRUCK DIGIT ZERO
    "\U0001d7d9": "l",  # MATHEMATICAL DOUBLE-STRUCK DIGIT ONE
    "\U0001d7e2": "O",  # MATHEMATICAL SANS-SERIF DIGIT ZERO
    "\U0001d7e3": "l",  # MATHEMATICAL SANS-SERIF DIGIT ONE
    "\U0001d7ec": "O",  # MATHEMATICAL SANS-SERIF BOLD DIGIT ZERO
    "\U0001d7ed": "l",  # MATHEMATICAL SANS-SERIF BOLD DIGIT ONE
    "\U0001d7f6": "O",  # MATHEMATICAL MONOSPACE DIGIT ZERO
    "\U0001d7f7": "l",  # MATHEMATICAL MONOSPACE DIGIT ONE
    "\U0001e8c7": "l",  # MENDE KIKAKUI DIGIT ONE
    "\U0001e8cb": "8",  # MENDE KIKAKUI DIGIT FIVE
    "\U0001ee00": "l",  # ARABIC MATHEMATICAL ALEF
    "\U0001ee24": "o",  # ARABIC MATHEMATICAL INITIAL HEH
    "\U0001ee64": "o",  # ARABIC MATHEMATICAL STRETCHED HEH
    "\U0001ee80": "l",  # ARABIC MATHEMATICAL LOOPED ALEF
    "\U0001ee84": "o",  # ARABIC MATHEMATICAL LOOPED HEH
    "\U0001f74c": "C",  # ALCHEMICAL SYMBOL FOR CALX
    "\U0001f768": "T",  # ALCHEMICAL SYMBOL FOR CRUCIBLE-4
    "\U0001fbf0": "O",  # SEGMENTED DIGIT ZERO
    "\U0001fbf1": "l",  # SEGMENTED DIGIT ONE
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
    "\u00ad": "-",  # Soft hyphen
    "\ufe58": "-",  # Small em dash (﹘)
    "\ufe63": "-",  # Small hyphen-minus (﹣) — NFKC covers this but be explicit
    "\uff0d": "-",  # Fullwidth hyphen-minus (－) — NFKC covers this but be explicit
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
        "\u200e",
        "\u200f",  # LRM, RLM
        "\u200c",
        "\u200d",  # ZWNJ, ZWJ (homoglyph risk)
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",  # Bidi overrides
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",  # Bidi isolates
        "\u00ad",  # Soft hyphen
        "\ufeff",  # BOM / ZWNBSP
    }
    text = "".join(
        c
        for c in text
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
    text = text.replace("://", "\u200b://")
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
    text = re.sub(r"\x1b\[[0-9;]*[@-~]", "", text)
    # OSC terminator is optional — unterminated sequences (no BEL or ST)
    # must also be stripped to prevent payload leakage (same as PM/APC/SOS/DCS).
    text = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?", "", text)
    # Strip PM (ESC ^...ST) and APC (ESC _...ST) sequences.
    # Also strip SOS (ESC X...ST) and DCS (ESC P...ST) sequences.
    # ECMA-48 §5.6 defines six C1 control strings; we now cover all of them.
    # ST terminator is now optional — unterminated control strings
    # (payload with no ESC \) are also stripped to prevent payload leakage.
    text = re.sub(r"\x1b[\^_XP][^\x1b]*(?:\x1b\\)?", "", text)
    # Strip remaining control characters:
    # - C0 range (0x00-0x1F except tab)
    # - DEL (0x7F) — erases characters in some terminals
    # 8-bit C1 controls (0x80-0x9F) — single-byte equivalents of
    # ESC-based C1 sequences (e.g., U+009B = CSI, U+0090 = DCS). Some terminals
    # interpret these as control sequences even in UTF-8 mode.
    text = "".join(
        c
        for c in text
        if (ord(c) >= 0x20 or c == "\t")
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
        errors="replace",  # Replace undecodable bytes rather than crash
        check=False,
        timeout=GIT_TIMEOUT,  # Prevent indefinite hangs
        env=_GIT_SAFE_ENV,  # Prevent auth hangs
    )
    if result.returncode != 0:
        # Truncate stderr and redact command args to prevent leaking
        # internal format strings, paths, or auth details
        stderr_safe = result.stderr.strip().split("\n")[0][:200]
        # Redact anything that looks like a filesystem path to
        # prevent leaking internal directory structure in error messages.
        # Unix paths (/foo/bar) and Windows paths (C:\foo\bar).
        stderr_safe = re.sub(r"/[\w./-]{5,}", "<path>", stderr_safe)
        stderr_safe = re.sub(r"[A-Za-z]:[\\][\w.\\/-]{3,}", "<path>", stderr_safe)
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
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
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
        [
            "git",
            "--no-optional-locks",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            parent,
            sha,
        ],
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
            chunk = proc.stdout.read(65536)  # type: ignore[union-attr]
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
        proc.stdout.close()  # type: ignore[union-attr]
    # Final wait with timeout — kill if git hangs during cleanup.
    _killed_for_cleanup = False
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:  # pragma: no cover
        proc.kill()
        proc.wait()
        _killed_for_cleanup = True
    if proc.returncode != 0 and not _killed_for_cleanup:
        raise RuntimeError(
            f"git diff {parent} {sha} failed (exit code {proc.returncode})"
        )
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
            return urlunparse(
                parsed._replace(
                    netloc=clean_netloc,
                    query="",
                    fragment="",
                )
            )
    except Exception:  # pragma: no cover
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
    # EXCEPTION: U+00AD (soft hyphen) is Cf but should be converted to '-'
    # by _DASH_TO_ASCII, not stripped.  Stripping it removes the hyphen
    # entirely ("co\u00ADauthored" → "coauthored" instead of "co-authored").
    text = "".join(c for c in text if unicodedata.category(c) != "Cf" or c == "\u00ad")
    # NFKC collapses compatibility variants (e.g., fullwidth Ｃ→C)
    text = unicodedata.normalize("NFKC", text)
    # Normalize Unicode dash/hyphen variants to ASCII '-'
    text = "".join(_DASH_TO_ASCII.get(c, c) for c in text)
    # Resolve cross-script homoglyphs that NFKC doesn't cover
    text = "".join(_CONFUSABLE_TO_ASCII.get(c, c) for c in text)
    # NFD decomposition before Mn stripping — NFKC sometimes composes
    # base+combining into a single precomposed codepoint (e.g., o+\u0303 → õ)
    # which has category Ll, not Mn, and would survive Mn stripping.
    # NFD decomposes it back so the combining mark can be stripped.
    text = unicodedata.normalize("NFD", text)
    # Strip combining marks (Mn) and enclosing marks (Me) — variation
    # selectors and diacriticals that survive NFKC
    text = "".join(c for c in text if unicodedata.category(c) not in ("Mn", "Me"))
    return text
