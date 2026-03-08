#!/usr/bin/env python3
"""
AIIR — AI Integrity Receipts

Generate cryptographic receipts for git commits. Detects AI authorship signals
(Copilot, ChatGPT, Claude, Cursor, Aider, etc.) and produces content-addressed
JSON receipts suitable for audit trails and compliance.

Zero dependencies — uses only Python standard library.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0

This module is the public API surface and CLI entry point.
Implementation is split across _core, _detect, _receipt, _ledger,
_stats, _github, _verify, and _sign submodules.  All symbols are
re-exported here for backward compatibility.
"""

from __future__ import annotations

import argparse
import difflib
import json
import logging
import os
import subprocess
import sys
from typing import Any, Dict, List, NoReturn, Optional, Sequence
from urllib.parse import urlunparse  # noqa: F401 — used by tests (cli_mod.urlunparse)

# ---------------------------------------------------------------------------
# Re-export everything from submodules so that existing imports such as
#     import aiir.cli as cli; cli.detect_ai_signals(...)
# and
#     from aiir.cli import generate_receipt, verify_receipt_file
# continue to work without changes.
# ---------------------------------------------------------------------------

from aiir._core import (  # noqa: F401
    RECEIPT_SCHEMA_VERSION,
    CLI_VERSION,
    MAX_RECEIPTS_PER_RANGE,
    MAX_RECEIPT_FILE_SIZE,
    MAX_SUMMARY_SIZE,
    LEDGER_DIR as _LEDGER_DIR,
    GIT_TIMEOUT,
    _GIT_SAFE_ENV,
    _EMOJI,
    _BOX,
    _can_encode,
    _USE_EMOJI,
    _USE_BOXDRAW,
    _e,
    _b,
    _HAS_FCHMOD,
    _validate_ref,
    _sanitize_md,
    CommitInfo,
    _strip_terminal_escapes,
    _run_git,
    _sha256,
    _canonical_json,
    _MAX_JSON_DEPTH,
    _check_json_depth,
    _hash_diff_streaming,
    _strip_url_credentials,
    _now_rfc3339,
    get_repo_root,
    _normalize_for_detection,
    logger,
)

from aiir._detect import (  # noqa: F401
    AI_SIGNALS,
    AI_TRAILERS,
    detect_ai_signals,
    get_commit_info,
    list_commits_in_range,
)

from aiir._receipt import (  # noqa: F401
    build_commit_receipt,
    generate_receipt,
    generate_receipts_for_range,
    format_receipt_pretty,
    write_receipt,
)

from aiir._ledger import (  # noqa: F401
    _ledger_paths,
    _config_path,
    _load_config,
    _save_config,
    _load_index,
    _save_index,
    append_to_ledger,
    export_ledger,
)

from aiir._stats import (  # noqa: F401
    format_badge,
    format_stats,
    check_policy,
)

from aiir._github import (  # noqa: F401
    set_github_output,
    set_github_summary,
    format_github_summary,
)

from aiir._verify import (  # noqa: F401
    verify_receipt,
    verify_receipt_file,
)

from aiir._sign import (  # noqa: F401
    _sigstore_available,
    sign_receipt,
    sign_receipt_file,
    verify_receipt_signature,
)


# ---------------------------------------------------------------------------
# Override _e / _b so they read _USE_EMOJI / _USE_BOXDRAW from THIS module's
# globals.  Tests toggle  cli._USE_EMOJI = False  and expect  cli._e("ok")
# to return ASCII.  The originals in _core read _core._USE_EMOJI, so a
# rebind on cli wouldn't propagate.  Defining the wrappers here fixes that.
# ---------------------------------------------------------------------------

def _e(name: str) -> str:  # noqa: F811 — intentional override
    """Return emoji glyph if the terminal supports it, else ASCII fallback."""
    pair = _EMOJI.get(name)
    if pair is None:
        return ""
    return pair[0] if _USE_EMOJI else pair[1]


def _b(name: str) -> str:  # noqa: F811 — intentional override
    """Return box-drawing glyph if the terminal supports it, else ASCII."""
    pair = _BOX.get(name)
    if pair is None:
        return ""
    return pair[0] if _USE_BOXDRAW else pair[1]


# ---------------------------------------------------------------------------
# CLI main
# ---------------------------------------------------------------------------


# Subclass ArgumentParser to show did-you-mean suggestions when
# the user passes an unrecognised flag (e.g. --prettty → did you mean --pretty?).
class _FriendlyParser(argparse.ArgumentParser):
    """ArgumentParser that suggests close matches for unrecognised flags."""

    def error(self, message: str) -> NoReturn:  # noqa: D401 (argparse override)
        if "unrecognized arguments:" in message:
            bad = message.split("unrecognized arguments:")[-1].strip().split()
            # Sanitise user tokens before echoing to stderr
            safe_bad = " ".join(_strip_terminal_escapes(t) for t in bad)
            known = [a.option_strings for a in self._actions if a.option_strings]
            flat = [f for opts in known for f in opts]
            hints = []
            for token in bad:
                close = difflib.get_close_matches(token, flat, n=1, cutoff=0.6)
                if close:
                    hints.append(f"  {_e('hint')} Did you mean {close[0]} ?")
            if hints:
                self.exit(
                    2,
                    f"{_e('error')} Unknown flag: {safe_bad}\n"
                    + "\n".join(hints) + "\n",
                )
            # Always use friendly format, no fallthrough
            self.exit(2, f"{_e('error')} Unknown flag: {safe_bad}\n")
        # Fall through for all other argparse errors (including
        # mutually-exclusive group violations) — keep default behaviour.
        super().error(message)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point."""
    parser = _FriendlyParser(
        prog="aiir",
        description="AIIR - AI Integrity Receipts. Generate cryptographic receipts for git commits.",
        epilog=(
            "examples:\n"
            "  aiir                        Receipt HEAD → .aiir/receipts.jsonl\n"
            "  aiir --pretty               Same, plus human-readable summary\n"
            "  aiir -r origin/main..HEAD   Receipt every commit in a range\n"
            "  aiir --ai-only              Only AI-authored commits\n"
            "  aiir --json                 Print JSON to stdout (for piping)\n"
            "  aiir -o .receipts           Individual receipt files in a dir\n"
            "  aiir --verify receipt.json   Verify a receipt's integrity\n"
            "  aiir --sign -o .receipts    Sign receipt with Sigstore\n"
            "\n"
            "default: receipts are appended to .aiir/receipts.jsonl and\n"
            "auto-indexed in .aiir/index.json (one entry per commit SHA,\n"
            "duplicates skipped).  Add .aiir/ to your repo for an audit trail.\n"
            "\n"
            "exit codes:\n"
            "  0  Success (receipts generated, or verification passed)\n"
            "  1  Error (verification failed, git error, bad input)\n"
            "\n"
            "https://github.com/invariant-systems-ai/aiir  |  "
            "https://invariantsystems.io"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--commit",
        "-c",
        default=None,
        help="Specific commit SHA to receipt (default: HEAD)",
    )
    parser.add_argument(
        "--range",
        "-r",
        default=None,
        dest="range_spec",
        help="Commit range to receipt (e.g., 'origin/main..HEAD')",
    )
    parser.add_argument(
        "--ai-only",
        action="store_true",
        help="Only generate receipts for AI-authored commits",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output directory for individual receipt JSON files (for CI)",
    )
    parser.add_argument(
        "--ledger",
        "-l",
        nargs="?",
        const=_LEDGER_DIR,
        default=None,
        help=(
            "Append receipts to a JSONL ledger (default: .aiir/receipts.jsonl). "
            "Duplicates are auto-skipped via .aiir/index.json. "
            "This is the default when no output flags are given."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_stdout",
        help="Print raw JSON to stdout instead of writing to ledger (for piping)",
    )
    parser.add_argument(
        "--jsonl",
        action="store_true",
        help="Output as JSON Lines to stdout (one receipt per line)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Print human-readable summary (combines with ledger by default)",
    )
    parser.add_argument(
        "--github-action",
        action="store_true",
        help="Run in GitHub Actions mode (set outputs + step summary)",
    )
    # --quiet and --verbose are mutually exclusive.
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress non-essential output",
    )
    verbosity_group.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug logging (git commands, timing, signal evaluation)",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"aiir {CLI_VERSION}",
    )
    parser.add_argument(
        "--verify",
        default=None,
        metavar="FILE",
        help="Verify a receipt JSON file's content-addressed integrity",
    )
    parser.add_argument(
        "--sign",
        action="store_true",
        help="Sign receipts using Sigstore keyless signing (requires pip install sigstore)",
    )
    parser.add_argument(
        "--verify-signature",
        action="store_true",
        help="Also verify Sigstore signature when using --verify (looks for .sigstore bundle)",
    )
    parser.add_argument(
        "--signer-identity",
        default=None,
        metavar="IDENTITY",
        help="Expected signer identity for --verify-signature (email or OIDC subject)",
    )
    parser.add_argument(
        "--signer-issuer",
        default=None,
        metavar="ISSUER",
        help="Expected OIDC issuer URL for --verify-signature",
    )
    parser.add_argument(
        "--redact-files",
        action="store_true",
        help="Omit individual file paths from receipts (privacy; mitigates I-05 file enumeration)",
    )
    parser.add_argument(
        "--namespace",
        default=None,
        metavar="NS",
        help="Tag receipts with an organization namespace (e.g., 'acme-corp')",
    )
    parser.add_argument(
        "--export",
        nargs="?",
        const="aiir-export.json",
        default=None,
        metavar="FILE",
        help="Export .aiir/ ledger as a portable JSON bundle (for backup or import)",
    )
    parser.add_argument(
        "--badge",
        action="store_true",
        help="Print a shields.io badge Markdown snippet from ledger stats",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print a summary dashboard of ledger statistics",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run policy checks against ledger stats (for CI gates)",
    )
    parser.add_argument(
        "--max-ai-percent",
        type=float,
        default=None,
        metavar="N",
        help="Policy gate: fail if AI-authored percentage exceeds N (use with --check)",
    )

    args = parser.parse_args(argv)

    # Configure logging based on --verbose flag or AIIR_LOG_LEVEL env.
    log_level = os.environ.get("AIIR_LOG_LEVEL", "DEBUG" if args.verbose else "WARNING")
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.WARNING),
        format="%(name)s %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    # --- Verify mode (no git repo needed) ---
    if args.verify:
        result = verify_receipt_file(args.verify)
        if result.get("valid"):
            count = result.get("count", 1)
            print(
                f"{_e('ok')} All good! {count} receipt{'s' if count != 1 else ''} verified -- integrity intact.",
                file=sys.stderr,
            )
            if "receipts" in result:
                for r in result["receipts"]:
                    print(
                        f"   {r['receipt_id'][:24]}... "
                        f"commit={r['commit_sha'][:12]} {_e('check')}",
                        file=sys.stderr,
                    )
            else:
                print(
                    f"   {result['receipt_id'][:24]}... "
                    f"commit={result['commit_sha'][:12]} {_e('check')}",
                    file=sys.stderr,
                )

            # Sigstore signature verification (optional)
            if args.verify_signature:
                sig_result = verify_receipt_signature(
                    args.verify,
                    expected_identity=args.signer_identity,
                    expected_issuer=args.signer_issuer,
                )
                result["signature"] = sig_result
                if sig_result.get("valid"):
                    policy = sig_result.get("policy", "any")
                    print(
                        f"{_e('ok')} Signature verified (policy={policy})",
                        file=sys.stderr,
                    )
                else:
                    sig_err = sig_result.get("error", "Unknown signature error")
                    print(
                        f"{_e('error')} Signature FAILED: {sig_err}",
                        file=sys.stderr,
                    )
                    print(json.dumps(result, indent=2))
                    return 1

            print(json.dumps(result, indent=2))
            return 0
        else:
            # When an array of receipts has failures, show
            # which specific receipts failed instead of a generic message.
            if "receipts" in result:
                failed = [r for r in result["receipts"] if not r.get("valid")]
                total = result.get("count", len(result["receipts"]))
                print(
                    f"{_e('error')} Verification failed: {len(failed)} of {total}"
                    f" receipt{'s' if total != 1 else ''} invalid.",
                    file=sys.stderr,
                )
                for r in failed[:5]:
                    rid = str(r.get("receipt_id", "unknown"))[:24]
                    errs = r.get("errors", [])
                    err_msg = errs[0] if errs else "content hash mismatch"
                    print(f"   * {rid}... -- {err_msg}", file=sys.stderr)
            else:
                error = result.get("error", "Content hash mismatch -- receipt may be tampered")
                print(f"{_e('error')} Verification failed: {error}", file=sys.stderr)
            # Context-aware verify tips — "receipt was changed" is
            # misleading for file-not-found and parse errors.  Show a tip that
            # matches the actual failure category.
            error_str = str(result.get("error", ""))
            if "File not found" in error_str:
                print(
                    f"   {_e('hint')} Check the file path and try again.",
                    file=sys.stderr,
                )
            elif "Invalid JSON" in error_str or "not a dict" in error_str:
                print(
                    f"   {_e('hint')} The file doesn't look like an aiir receipt."
                    " Receipts are JSON objects (or arrays of objects).",
                    file=sys.stderr,
                )
            elif "symlink" in error_str:
                print(
                    f"   {_e('hint')} Point --verify at the actual file, not a symlink.",
                    file=sys.stderr,
                )
            elif "too large" in error_str:
                print(
                    f"   {_e('hint')} The file exceeds the size limit."
                    " Is this the right file?",
                    file=sys.stderr,
                )
            else:
                print(
                    f"   {_e('hint')} This means the receipt was changed after it was created,"
                    " or it wasn't generated by aiir.",
                    file=sys.stderr,
                )
            print(json.dumps(result, indent=2))
            return 1

    # --- Export mode (no git repo needed) ---
    if args.export is not None:
        # Guard: fail early if no ledger exists (matches --badge / --stats).
        try:
            _idx = _load_index(_ledger_paths()[2])
        except OSError:
            _idx = {}
        if _idx.get("receipt_count", 0) == 0:
            print(
                f"{_e('error')} No ledger found — run 'aiir' first to generate receipts.",
                file=sys.stderr,
            )
            return 1
        try:
            bundle = export_ledger()
        except Exception as e:
            print(f"{_e('error')} Export failed: {e}", file=sys.stderr)
            return 1
        export_path = args.export
        # Validate export path — reject path traversal.
        if ".." in export_path or export_path.startswith("/"):
            print(f"{_e('error')} Export path must be relative and within the project.", file=sys.stderr)
            return 1
        from pathlib import Path
        out = Path(export_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(bundle, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        n = len(bundle.get("receipts", []))
        iid = bundle.get("instance_id", "none")[:8]
        print(
            f"{_e('ok')} Exported {n} receipt{'s' if n != 1 else ''} → {export_path}  (instance: {iid}…)",
            file=sys.stderr,
        )
        return 0

    # --- Badge mode (no git repo needed) ---
    if args.badge:
        try:
            idx = _load_index(_ledger_paths()[2])
        except OSError:
            idx = {}
        if idx.get("receipt_count", 0) == 0:
            print(f"{_e('error')} No ledger found — run 'aiir' first to generate receipts.", file=sys.stderr)
            return 1
        cfg = {}
        try:
            cfg = _load_config()
        except OSError:
            pass
        badge = format_badge(idx, namespace=cfg.get("namespace"))
        print(badge["markdown"])
        print(file=sys.stderr)
        print(f"   {_e('hint')} Paste into your README.md for an AI transparency badge.", file=sys.stderr)
        print(f"   URL: {badge['url']}", file=sys.stderr)
        return 0

    # --- Stats mode (no git repo needed) ---
    if args.stats:
        try:
            idx = _load_index(_ledger_paths()[2])
        except OSError:
            idx = {}
        if idx.get("receipt_count", 0) == 0:
            print(f"{_e('error')} No ledger found — run 'aiir' first to generate receipts.", file=sys.stderr)
            return 1
        cfg = {}
        try:
            cfg = _load_config()
        except OSError:
            pass
        print(format_stats(idx, config=cfg), file=sys.stderr)
        return 0

    # --- Check / policy gate mode (no git repo needed) ---
    if args.check or args.max_ai_percent is not None:
        try:
            idx = _load_index(_ledger_paths()[2])
        except OSError:
            idx = {}
        passed, message = check_policy(
            idx, max_ai_percent=args.max_ai_percent,
        )
        if passed:
            print(f"{_e('ok')} {message}", file=sys.stderr)
            return 0
        else:
            print(f"{_e('error')} {message}", file=sys.stderr)
            return 1

    # --- Receipt generation mode ---
    try:
        cwd = get_repo_root()
    except RuntimeError:
        print(f"{_e('error')} Not a git repository.", file=sys.stderr)
        print(
            f"   {_e('hint')} cd into your project first, or run 'git init' to start one.",
            file=sys.stderr,
        )
        return 1
    except FileNotFoundError:
        # Git binary not found on PATH
        print(f"{_e('error')} Can't find git!", file=sys.stderr)
        print(
            f"   {_e('hint')} Install it: https://git-scm.com/downloads",
            file=sys.stderr,
        )
        return 1
    except OSError as e:
        # Catch OS-level errors from get_repo_root() such as
        # permission denied on .git/HEAD, network mount dropped, or
        # corrupted working tree.  Without this the OSError produces an
        # unhandled traceback that leaks internal paths.
        print(f"{_e('error')} Something went wrong: {e}", file=sys.stderr)
        print(
            f"   {_e('hint')} Check that you have permission to read this repo.",
            file=sys.stderr,
        )
        return 1

    receipts: List[Dict[str, Any]] = []

    # Determine output mode early — config loading creates .aiir/ so
    # we only load it when the ledger (or explicit --namespace) is active.
    explicit_stdout = args.json_stdout or args.jsonl
    use_ledger = not explicit_stdout and not args.output and not args.github_action
    if args.ledger is not None:
        use_ledger = True

    # Load config for instance_id and namespace only when .aiir/ will be
    # used anyway (ledger mode) or the user explicitly set --namespace.
    instance_id: Optional[str] = None
    namespace: Optional[str] = getattr(args, "namespace", None)
    if use_ledger or namespace:
        try:
            config = _load_config()
        except OSError:
            config = {}
        instance_id = config.get("instance_id")
        namespace = namespace or config.get("namespace")
        # Persist namespace to config if set via CLI flag.
        if getattr(args, "namespace", None) and args.namespace != config.get("namespace"):
            config["namespace"] = args.namespace
            try:
                _save_config(_config_path(), config)
            except OSError:
                pass

    try:
        if args.range_spec:
            receipts = generate_receipts_for_range(
                args.range_spec, cwd=cwd, ai_only=args.ai_only,
                redact_files=args.redact_files,
                instance_id=instance_id, namespace=namespace,
            )
        else:
            commit_ref = args.commit or "HEAD"
            receipt = generate_receipt(
                commit_ref, cwd=cwd, ai_only=args.ai_only,
                redact_files=args.redact_files,
                instance_id=instance_id, namespace=namespace,
            )
            if receipt:
                receipts = [receipt]
    except (RuntimeError, ValueError) as e:
        # Detect empty repo (no commits) and show a friendly
        # message instead of leaking the raw git stderr.
        err_str = str(e)
        if "unknown revision" in err_str or "bad default revision" in err_str:
            print(f"{_e('error')} No commits yet.", file=sys.stderr)
            print(
                f"   {_e('hint')} Make your first commit, then run aiir again.",
                file=sys.stderr,
            )
        else:
            print(f"{_e('error')} {e}", file=sys.stderr)
        return 1
    except OSError as e:
        # Catch filesystem errors (e.g., network mount dropped,
        # permission denied on .git, corrupted working tree). Without this,
        # an OSError from subprocess or file I/O produces an unhandled
        # traceback that leaks internal paths.
        print(f"{_e('error')} {e}", file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        # Git subprocess timeout — surface a clean message instead of
        # an unhandled traceback that leaks internal paths and command strings.
        print(
            f"{_e('error')} Git took too long (>{GIT_TIMEOUT}s). Is the repo very large?",
            file=sys.stderr,
        )
        print(
            f"   {_e('hint')} Try a smaller commit range, or check your network connection.",
            file=sys.stderr,
        )
        return 1

    if not receipts:
        if not args.quiet:
            if args.ai_only:
                print(
                    f"{_e('shrug')} No AI-authored commits found -- --ai-only filtered everything out.",
                    file=sys.stderr,
                )
                print(
                    f"   {_e('hint')} Remove --ai-only to receipt all commits.",
                    file=sys.stderr,
                )
            else:
                print(f"{_e('shrug')} Nothing to receipt here.", file=sys.stderr)
                if args.range_spec:
                    # Sanitize range_spec — user input may
                    # contain terminal escape sequences.
                    print(
                        f"   {_e('hint')} The range may be empty -- check: "
                        "git log --oneline " + _strip_terminal_escapes(args.range_spec),
                        file=sys.stderr,
                    )
                else:
                    print(
                        f"   {_e('hint')} Make sure you have at least one commit: git log --oneline -1",
                        file=sys.stderr,
                    )
        if args.github_action:
            set_github_output("receipt_count", "0")
            set_github_output("ai_commit_count", "0")
        return 0

    # Validate signing requirements
    if args.sign and not args.output:
        print(
            f"{_e('error')} --sign needs --output too (bundles are saved as sidecar files).",
            file=sys.stderr,
        )
        print(
            f"   {_e('hint')} Try: aiir --sign --output .receipts",
            file=sys.stderr,
        )
        return 1
    if args.sign and not _sigstore_available():
        print(
            f"{_e('error')} Signing needs the 'sigstore' package.",
            file=sys.stderr,
        )
        print(
            f"   {_e('hint')} Install it: pip install sigstore",
            file=sys.stderr,
        )
        return 1

    # ── Determine output mode ──────────────────────────────────────────
    # (use_ledger was computed earlier to control config loading)
    # --pretty is orthogonal — it prints to stderr and combines with any mode.

    # ── Output ─────────────────────────────────────────────────────────
    signed_count = 0
    stdout_json_receipts: List[Dict[str, Any]] = []

    # Pretty-print (always goes to stderr so it can combine with any mode).
    if args.pretty:
        for receipt in receipts:
            print(format_receipt_pretty(receipt), file=sys.stderr)

    # Mode A: individual files (--output / --sign)
    if args.output or args.sign:
        for receipt in receipts:
            try:
                path = write_receipt(receipt, output_dir=args.output, jsonl=args.jsonl)
            except ValueError as e:
                print(f"{_e('error')} {e}", file=sys.stderr)
                print(
                    f"   {_e('hint')} Use a folder inside your project, e.g. --output .receipts",
                    file=sys.stderr,
                )
                return 1
            if args.sign and path and not path.startswith("stdout:"):
                try:
                    bundle_path = sign_receipt_file(path)
                    signed_count += 1
                    if not args.quiet:
                        print(
                            f"  {_e('signed')} Signed: {bundle_path}",
                            file=sys.stderr,
                        )
                except Exception as e:
                    err_msg = _strip_terminal_escapes(str(e))[:200]
                    print(f"{_e('error')} Signing failed: {err_msg}", file=sys.stderr)
                    print(
                        f"   {_e('hint')} Check your internet connection and try again.",
                        file=sys.stderr,
                    )
                    return 1

    # Mode B: stdout (--json or --jsonl)
    if explicit_stdout:
        if args.jsonl:
            for receipt in receipts:
                try:
                    write_receipt(receipt, output_dir=None, jsonl=True)
                except ValueError as e:
                    print(f"{_e('error')} {e}", file=sys.stderr)
                    return 1
        else:
            # --json: single object or array
            if len(receipts) == 1:
                print(json.dumps(receipts[0], indent=2, ensure_ascii=False), flush=True)
            else:
                print(json.dumps(receipts, indent=2, ensure_ascii=False), flush=True)

    # Mode C: ledger (default)
    if use_ledger:
        ledger_dir = args.ledger if args.ledger is not None else _LEDGER_DIR
        try:
            appended, skipped_count, ledger_path = append_to_ledger(
                receipts, ledger_dir=ledger_dir,
            )
        except ValueError as e:
            print(f"{_e('error')} {e}", file=sys.stderr)
            return 1

    # ── Compute stats ──────────────────────────────────────────────────
    ai_count = sum(
        1
        for r in receipts
        if r.get("ai_attestation", {}).get("is_ai_authored")
    )

    # ── Summary (stderr) ───────────────────────────────────────────────
    if not args.quiet and not args.jsonl:
        n = len(receipts)
        parts = [f"{_e('ok')} {n} receipt{'s' if n != 1 else ''} generated"]
        if ai_count:
            parts.append(f"{_e('ai')} {ai_count} AI-authored")
        if signed_count:
            parts.append(f"{_e('signed')} {signed_count} signed")
        print("\n" + " | ".join(parts), file=sys.stderr)

        if use_ledger:
            print(
                f"   {_e('hint')} Saved to {ledger_path}"  # type: ignore[possibly-undefined]
                + (f" ({skipped_count} duplicate{'s' if skipped_count != 1 else ''} skipped)"  # type: ignore[possibly-undefined]
                   if skipped_count else ""),  # type: ignore[possibly-undefined]
                file=sys.stderr,
            )

    # Unsigned receipt warning
    if not args.sign and not args.quiet and receipts:
        print(file=sys.stderr)
        print(
            f"{_e('tip')} Tip: these receipts are unsigned. Add --sign for "
            f"Sigstore keyless signing (default in GitHub Actions).",
            file=sys.stderr,
        )

    # Privacy hint
    if not args.redact_files and not args.quiet and receipts:
        print(
            f"   {_e('hint')} Receipts include author emails and filenames. "
            "Add --redact-files to omit file paths.",
            file=sys.stderr,
        )

    # GitHub Actions integration
    if args.github_action:
        set_github_output("receipt_count", str(len(receipts)))
        set_github_output("ai_commit_count", str(ai_count))
        _MAX_OUTPUT_SIZE = 1024 * 1024  # 1 MB
        receipts_payload = _canonical_json(receipts)
        if len(receipts_payload.encode("utf-8", errors="replace")) > _MAX_OUTPUT_SIZE:
            set_github_output("receipts_json", '"OVERFLOW"')
            set_github_output("receipts_overflow", "true")
            print(
                f"WARNING: receipts_json exceeds 1 MB ({len(receipts_payload)} bytes) "
                f"-- output set to OVERFLOW. Use --output to write receipts to files.",
                file=sys.stderr,
            )
        else:
            set_github_output("receipts_json", receipts_payload)

        summary = format_github_summary(receipts)
        set_github_summary(summary)

    return 0


if __name__ == "__main__":
    sys.exit(main())
