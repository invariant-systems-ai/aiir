"""Tests for core utilities (hashing, sanitisation, helpers)."""
# Copyright 2025-2026 Invariant Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

# Import the module under test
import aiir.cli as cli


def _make_test_receipt():
    """Create a minimal valid receipt for testing."""
    commit = cli.CommitInfo(
        sha="deadbeef12345678",
        author_name="Test User",
        author_email="test@example.com",
        author_date="2026-01-01T00:00:00Z",
        committer_name="Test User",
        committer_email="test@example.com",
        committer_date="2026-01-01T00:00:00Z",
        subject="test: cross-platform",
        body="test: cross-platform\n",
        diff_stat="1 file changed, 1 insertion(+)",
        diff_hash="sha256:0000",
        files_changed=["test.py"],
        is_ai_authored=False,
        ai_signals_detected=[],
    )
    with patch.object(cli, "_run_git", return_value="https://example.com/repo"):
        return cli.build_commit_receipt(commit)


class TestValidateRef(unittest.TestCase):
    """Tests for _validate_ref() — VULN-03 argument injection prevention."""

    def test_normal_ref(self):
        self.assertEqual(cli._validate_ref("HEAD"), "HEAD")
        self.assertEqual(cli._validate_ref("main..HEAD"), "main..HEAD")
        self.assertEqual(cli._validate_ref("abc123"), "abc123")

    def test_rejects_single_dash_option(self):
        with self.assertRaises(ValueError):
            cli._validate_ref("-n 5")

    def test_rejects_double_dash_option(self):
        with self.assertRaises(ValueError):
            cli._validate_ref("--all")

    def test_rejects_remotes_flag(self):
        with self.assertRaises(ValueError):
            cli._validate_ref("--remotes")

    def test_rejects_objects_flag(self):
        with self.assertRaises(ValueError):
            cli._validate_ref("--objects")

    def test_rejects_leading_whitespace_dash(self):
        with self.assertRaises(ValueError):
            cli._validate_ref("  --all")

    def test_allows_range_with_dots(self):
        self.assertEqual(cli._validate_ref("origin/main..HEAD"), "origin/main..HEAD")

    def test_allows_triple_dot_range(self):
        self.assertEqual(cli._validate_ref("main...HEAD"), "main...HEAD")

    def test_rejects_path_traversal(self):
        with self.assertRaises(ValueError):
            cli._validate_ref("../../etc/passwd")
        with self.assertRaises(ValueError):
            cli._validate_ref("foo/../bar")

    def test_allows_sha(self):
        sha = "a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9"
        self.assertEqual(cli._validate_ref(sha), sha)


# ---------------------------------------------------------------------------
# Markdown sanitization tests (VULN-06)
# ---------------------------------------------------------------------------


class TestSanitizeMd(unittest.TestCase):
    """Tests for _sanitize_md() — VULN-06 markdown injection prevention."""

    def test_pipe_escaped(self):
        result = cli._sanitize_md("col1|col2")
        self.assertNotIn("|", result.replace("\\|", ""))

    def test_image_beacon_blocked(self):
        result = cli._sanitize_md("![x](https://evil.com/track)")
        # Both ! and [ should be escaped
        self.assertNotIn("![", result)

    def test_link_blocked(self):
        result = cli._sanitize_md("[click](https://evil.com)")
        # The opening bracket should be escaped, breaking markdown link syntax
        self.assertTrue(result.startswith("\\[") or "\\[" in result)

    def test_html_escaped(self):
        result = cli._sanitize_md("<script>alert(1)</script>")
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;", result)

    def test_normal_text_passes(self):
        text = "feat: add new auth middleware"
        result = cli._sanitize_md(text)
        self.assertEqual(result, text)

    def test_backtick_escaped(self):
        result = cli._sanitize_md("`code`")
        self.assertNotIn("`code`", result)


# ---------------------------------------------------------------------------
# Canonical JSON and hashing tests
# ---------------------------------------------------------------------------


class TestCanonicalJson(unittest.TestCase):
    """Tests for _canonical_json() determinism."""

    def test_sorted_keys(self):
        result = cli._canonical_json({"z": 1, "a": 2})
        self.assertEqual(result, '{"a":2,"z":1}')

    def test_no_whitespace(self):
        result = cli._canonical_json({"key": "value"})
        self.assertNotIn(" ", result)
        self.assertNotIn("\n", result)

    def test_deterministic(self):
        obj = {"b": [1, 2, 3], "a": {"nested": True}}
        r1 = cli._canonical_json(obj)
        r2 = cli._canonical_json(obj)
        self.assertEqual(r1, r2)


class TestHashing(unittest.TestCase):
    """Tests for SHA-256 helpers."""

    def test_sha256_known_value(self):
        # SHA-256 of empty string
        result = cli._sha256("")
        self.assertEqual(
            result,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_sha256_hello(self):
        result = cli._sha256("hello")
        self.assertEqual(
            result,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )


# ---------------------------------------------------------------------------
# Receipt build and verify round-trip tests
# ---------------------------------------------------------------------------


class TestNormalizeHelper(unittest.TestCase):
    """R12-TECH-02: _normalize_for_detection must be consistent and correct."""

    def test_strips_zwj(self):
        """Zero-width joiner (Cf) must be removed."""
        result = cli._normalize_for_detection("Co\u200dpilot")
        self.assertEqual(result, "Copilot")

    def test_resolves_cyrillic_homoglyphs(self):
        """Cyrillic homoglyphs must be resolved to Latin equivalents."""
        # "сopilot" with Cyrillic с (U+0441 → "c")
        result = cli._normalize_for_detection("\u0441opilot")
        self.assertEqual(result, "copilot")

    def test_strips_combining_marks(self):
        """Combining overlay marks (Mn) must be stripped."""
        # U+0336 (COMBINING LONG STROKE OVERLAY) has no precomposed form
        # with Latin letters, so NFKC preserves it — then Mn stripping removes it.
        result = cli._normalize_for_detection("C\u0336opilot")
        self.assertEqual(result, "Copilot")

    def test_message_and_name_field_consistency(self):
        """Message body path and name field path must produce same result."""
        test_input = "\u200dC\u0336\u0441ilot"  # ZWJ + combining overlay + cyrillic с
        msg_result = cli._normalize_for_detection(test_input)
        name_result = cli._normalize_for_detection(test_input)
        self.assertEqual(msg_result, name_result)
        # Cyrillic с (U+0441) → "c", combining mark stripped → "Ccilot"
        self.assertIn("c", msg_result.lower())

    def test_fullwidth_collapsed(self):
        """NFKC must collapse fullwidth characters."""
        # Fullwidth C = U+FF23
        result = cli._normalize_for_detection("\uff23opilot")
        self.assertEqual(result, "Copilot")

    def test_empty_string(self):
        """Empty string should return empty string."""
        self.assertEqual(cli._normalize_for_detection(""), "")


class TestSanitizeMdBackslash(unittest.TestCase):
    """R13-SEC-02: _sanitize_md must escape backslashes to prevent GFM breakout."""

    def test_backslash_pipe_table_breakout(self):
        r"""Input \| must NOT produce \\| (GFM: literal-\ + pipe-delimiter)."""
        result = cli._sanitize_md("hello\\|world")
        # In GFM, every | must be preceded by an odd number of backslashes
        # to be treated as a literal pipe.  Count backslashes before each |.
        for i, c in enumerate(result):
            if c == "|":
                count = 0
                j = i - 1
                while j >= 0 and result[j] == "\\":
                    count += 1
                    j -= 1
                self.assertEqual(
                    count % 2, 1, f"Unescaped | at position {i} in {result!r}"
                )

    def test_backslash_emphasis_bypass(self):
        r"""Input \*bold\* must NOT bypass emphasis escaping."""
        result = cli._sanitize_md("\\*bold\\*")
        # After escaping: \\ becomes \\\\, * becomes \*
        # So no bare * should remain after removing \\* sequences
        cleaned = result.replace("\\*", "")
        self.assertNotIn("*", cleaned)

    def test_double_backslash_pipe(self):
        r"""Input \\| must be properly escaped (\\\\| in GFM = two literal \ + pipe)."""
        result = cli._sanitize_md("\\\\|test")
        # Every | in output should have odd preceding backslash count
        for i, c in enumerate(result):
            if c == "|":
                count = 0
                j = i - 1
                while j >= 0 and result[j] == "\\":
                    count += 1
                    j -= 1
                self.assertEqual(
                    count % 2, 1, f"Unescaped | at position {i} in {result!r}"
                )

    def test_backslash_only(self):
        r"""A standalone backslash must be doubled."""
        result = cli._sanitize_md("a\\b")
        self.assertIn("\\\\", result)

    def test_backslash_underscore(self):
        r"""Input \_italic\_ must NOT bypass underscore escaping."""
        result = cli._sanitize_md("\\_italic\\_")
        cleaned = result.replace("\\_", "")
        self.assertNotIn("_", cleaned)

    def test_backslash_tilde(self):
        r"""Input \~strike\~ must NOT bypass tilde escaping."""
        result = cli._sanitize_md("\\~strike\\~")
        cleaned = result.replace("\\~", "")
        self.assertNotIn("~", cleaned)


class TestEmojiHelper(unittest.TestCase):
    """R19-PUB-01: _e() returns emoji on UTF-8, ASCII fallback otherwise."""

    def test_e_returns_emoji_when_supported(self):
        """_e() should return the emoji glyph when _USE_EMOJI is True."""
        original = cli._USE_EMOJI
        try:
            cli._USE_EMOJI = True
            self.assertEqual(cli._e("ok"), "\u2705")
            self.assertEqual(cli._e("error"), "\u274c")
            self.assertEqual(cli._e("hint"), "\U0001f4a1")
            self.assertEqual(cli._e("ai"), "\U0001f916")
            self.assertEqual(cli._e("signed"), "\U0001f58a\ufe0f")
            self.assertEqual(cli._e("tip"), "\U0001f4dd")
            self.assertEqual(cli._e("shrug"), "\U0001f937")
            self.assertEqual(cli._e("check"), "\u2714")
        finally:
            cli._USE_EMOJI = original

    def test_e_returns_ascii_fallback(self):
        """_e() should return ASCII text when _USE_EMOJI is False."""
        original = cli._USE_EMOJI
        try:
            cli._USE_EMOJI = False
            self.assertEqual(cli._e("ok"), "[ok]")
            self.assertEqual(cli._e("error"), "[error]")
            self.assertEqual(cli._e("hint"), "[hint]")
            self.assertEqual(cli._e("ai"), "[AI]")
            self.assertEqual(cli._e("signed"), "[signed]")
            self.assertEqual(cli._e("tip"), "[tip]")
            self.assertEqual(cli._e("shrug"), "[info]")
            self.assertEqual(cli._e("check"), "ok")
        finally:
            cli._USE_EMOJI = original

    def test_e_unknown_returns_empty(self):
        """_e() with an unknown name should return empty string."""
        self.assertEqual(cli._e("nonexistent"), "")
        self.assertEqual(cli._e(""), "")

    def test_ascii_fallbacks_are_pure_ascii(self):
        """Every fallback string in _EMOJI must encode cleanly as ASCII."""
        for name, (_, fallback) in cli._EMOJI.items():
            try:
                fallback.encode("ascii")
            except UnicodeEncodeError:
                self.fail(f"Fallback for {name!r} is not ASCII: {fallback!r}")

    def test_can_encode_detects_utf8(self):
        """_can_encode should return True for a UTF-8 probe in our env."""
        # Our test environment is UTF-8 — this should always be True.
        self.assertTrue(cli._can_encode("\u2705\U0001f916"))


class TestBoxDrawHelper(unittest.TestCase):
    """R19-PUB-02: _b() returns box-drawing on capable terminals, ASCII otherwise."""

    def test_b_returns_boxdraw_when_supported(self):
        """_b() should return Unicode box chars when _USE_BOXDRAW is True."""
        original = cli._USE_BOXDRAW
        try:
            cli._USE_BOXDRAW = True
            self.assertEqual(cli._b("tl"), "\u250c")
            self.assertEqual(cli._b("vl"), "\u2502")
            self.assertEqual(cli._b("bl"), "\u2514")
            self.assertEqual(cli._b("hl"), "\u2500")
        finally:
            cli._USE_BOXDRAW = original

    def test_b_returns_ascii_fallback(self):
        """_b() should return +/-/| when _USE_BOXDRAW is False."""
        original = cli._USE_BOXDRAW
        try:
            cli._USE_BOXDRAW = False
            self.assertEqual(cli._b("tl"), "+")
            self.assertEqual(cli._b("vl"), "|")
            self.assertEqual(cli._b("bl"), "+")
            self.assertEqual(cli._b("hl"), "-")
        finally:
            cli._USE_BOXDRAW = original

    def test_b_unknown_returns_empty(self):
        """_b() with an unknown name should return empty string."""
        self.assertEqual(cli._b("nonexistent"), "")

    def test_ascii_fallbacks_are_pure_ascii(self):
        """Every fallback string in _BOX must encode cleanly as ASCII."""
        for name, (_, fallback) in cli._BOX.items():
            try:
                fallback.encode("ascii")
            except UnicodeEncodeError:
                self.fail(f"Fallback for {name!r} is not ASCII: {fallback!r}")


class TestAsciiFallbackIntegration(unittest.TestCase):
    """Integration: full CLI output with _USE_EMOJI=False should be ASCII-safe."""

    def test_verify_fail_ascii_mode(self):
        """Verify failure in ASCII mode should use [error] and [hint]."""
        import tempfile

        tmpdir = tempfile.mkdtemp()
        try:
            tampered = Path(tmpdir, "bad.json")
            tampered.write_text(
                '{"type":"aiir.commit_receipt","schema":"aiir/commit_receipt.v1",'
                '"version":"1.0.0","commit":{"sha":"abc"},"ai_attestation":{},'
                '"provenance":{},"receipt_id":"g1-wrong","content_hash":"sha256:wrong"}'
            )
            orig_emoji = cli._USE_EMOJI
            try:
                cli._USE_EMOJI = False
                from io import StringIO

                captured_err = StringIO()
                with patch("sys.stderr", captured_err):
                    rc = cli.main(["--verify", str(tampered)])
                self.assertEqual(rc, 1)
                stderr_text = captured_err.getvalue()
                self.assertIn("[error]", stderr_text)
                self.assertIn("[hint]", stderr_text)
                # Must NOT contain any emoji codepoints
                for ch in stderr_text:
                    self.assertLess(
                        ord(ch),
                        0x2700,
                        f"Non-ASCII symbol U+{ord(ch):04X} in fallback output",
                    )
            finally:
                cli._USE_EMOJI = orig_emoji
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_pretty_output_ascii_mode(self):
        """format_receipt_pretty in ASCII mode should use +/-/| not box-drawing."""
        orig_box = cli._USE_BOXDRAW
        try:
            cli._USE_BOXDRAW = False
            receipt = {
                "receipt_id": "g1-abc123",
                "content_hash": "sha256:aaa",
                "commit": {
                    "sha": "abc123def456",
                    "subject": "test commit",
                    "author_name": "Test",
                    "author_email": "t@t.t",
                    "files_changed": 3,
                    "timestamp": "2025-01-01T00:00:00Z",
                },
                "ai_attestation": {"is_ai_authored": False},
            }
            result = cli.format_receipt_pretty(receipt)
            # Should use ASCII box chars
            self.assertIn("+- Receipt:", result)
            self.assertIn("|  Commit:", result)
            # Must NOT contain Unicode box-drawing chars
            for ch in result:
                code = ord(ch)
                if 0x2500 <= code <= 0x257F:
                    self.fail(f"Box-drawing char U+{code:04X} in fallback output")
        finally:
            cli._USE_BOXDRAW = orig_box

    def test_full_output_encodable_as_ascii(self):
        """In full ASCII fallback mode, verify-fail output must encode as ASCII."""
        import tempfile

        tmpdir = tempfile.mkdtemp()
        try:
            tampered = Path(tmpdir, "bad.json")
            tampered.write_text(
                '{"type":"aiir.commit_receipt","schema":"aiir/commit_receipt.v1",'
                '"version":"1.0.0","commit":{"sha":"abc"},"ai_attestation":{},'
                '"provenance":{},"receipt_id":"g1-x","content_hash":"sha256:x"}'
            )
            orig_emoji = cli._USE_EMOJI
            try:
                cli._USE_EMOJI = False
                from io import StringIO

                captured_err = StringIO()
                with patch("sys.stderr", captured_err):
                    cli.main(["--verify", str(tampered)])
                stderr_text = captured_err.getvalue()
                # The entire stderr output should be ASCII-encodable.
                try:
                    stderr_text.encode("ascii")
                except UnicodeEncodeError as e:
                    self.fail(f"Verify-fail stderr not ASCII-safe: {e}")
            finally:
                cli._USE_EMOJI = orig_emoji
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestNoRawEmojiInTerminalPaths(unittest.TestCase):
    """Regression: no raw emoji literals should appear in terminal-output code paths."""

    def test_no_raw_emoji_outside_emoji_dict(self):
        """cli.py should have no raw emoji in code outside the _EMOJI/_BOX dicts."""
        src = (Path(__file__).parent.parent / "aiir" / "cli.py").read_text(
            encoding="utf-8"
        )
        # Strip the _EMOJI and _BOX dict blocks (they legitimately contain emoji)
        # and format_github_summary (GitHub Markdown, not terminal output).
        # We look for any character above U+2700 outside those safe zones.
        lines = src.split("\n")
        in_safe_zone = False
        violations = []
        for i, line in enumerate(lines, 1):
            # Detect _EMOJI / _BOX dict blocks
            stripped = line.strip()
            if stripped.startswith("_EMOJI") or stripped.startswith("_BOX"):
                in_safe_zone = True
            if stripped.startswith("_CONFUSABLE") or stripped.startswith("_DASH"):
                in_safe_zone = True
            if stripped.startswith("}") and in_safe_zone:
                in_safe_zone = False
                continue
            # Detect format_github_summary (GitHub Markdown — emoji safe there)
            if "def format_github_summary" in line:
                in_safe_zone = True
            if (
                in_safe_zone
                and line.startswith("def ")
                and "format_github_summary" not in line
            ):
                in_safe_zone = False
            if in_safe_zone:
                continue
            # Check for emoji (U+2700+ range, excluding comments)
            if line.strip().startswith("#"):
                continue
            for ch in line:
                if ord(ch) >= 0x2700:
                    violations.append(
                        f"Line {i}: U+{ord(ch):04X} in: {line.strip()[:80]}"
                    )
        self.assertEqual(
            violations,
            [],
            "Raw emoji found outside safe zones:\n" + "\n".join(violations),
        )


class TestSummaryByteTruncation(unittest.TestCase):
    """R21-SEC-01: set_github_summary must truncate by byte count, not char count."""

    def test_multibyte_truncation_under_limit(self):
        """CJK text (3 bytes/char) must be truncated to stay under 1 MB."""
        # 400K CJK chars × 3 bytes = 1.2 MB → must be truncated
        text = "中" * 400_000
        self.assertGreater(len(text.encode("utf-8")), cli.MAX_SUMMARY_SIZE)

        import tempfile

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False)
        fname = f.name
        f.close()
        os.environ["GITHUB_STEP_SUMMARY"] = fname
        try:
            cli.set_github_summary(text)
            result = open(fname, "rb").read()
            # Written bytes must not exceed 1 MB + 1 byte for the trailing newline
            self.assertLessEqual(len(result), cli.MAX_SUMMARY_SIZE + 1)
        finally:
            del os.environ["GITHUB_STEP_SUMMARY"]
            os.unlink(fname)

    def test_emoji_truncation_under_limit(self):
        """Emoji text (4 bytes/char) must be truncated to stay under 1 MB."""
        # 300K emoji × 4 bytes = 1.2 MB → must be truncated
        text = "🔐" * 300_000
        self.assertGreater(len(text.encode("utf-8")), cli.MAX_SUMMARY_SIZE)

        import tempfile

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False)
        fname = f.name
        f.close()
        os.environ["GITHUB_STEP_SUMMARY"] = fname
        try:
            cli.set_github_summary(text)
            result = open(fname, "rb").read()
            self.assertLessEqual(len(result), cli.MAX_SUMMARY_SIZE + 1)
        finally:
            del os.environ["GITHUB_STEP_SUMMARY"]
            os.unlink(fname)

    def test_truncation_includes_suffix(self):
        """Truncated summary must include the truncation notice."""
        text = "X" * (cli.MAX_SUMMARY_SIZE + 100)
        import tempfile

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False)
        fname = f.name
        f.close()
        os.environ["GITHUB_STEP_SUMMARY"] = fname
        try:
            cli.set_github_summary(text)
            result = open(fname, "r").read()
            self.assertIn("truncated", result)
        finally:
            del os.environ["GITHUB_STEP_SUMMARY"]
            os.unlink(fname)

    def test_ascii_below_limit_not_truncated(self):
        """ASCII text below 1 MB must not be truncated."""
        text = "x" * 1000
        import tempfile

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False)
        fname = f.name
        f.close()
        os.environ["GITHUB_STEP_SUMMARY"] = fname
        try:
            cli.set_github_summary(text)
            result = open(fname, "r").read()
            self.assertNotIn("truncated", result)
            self.assertIn("x" * 1000, result)
        finally:
            del os.environ["GITHUB_STEP_SUMMARY"]
            os.unlink(fname)


class TestGitEnvHardening(unittest.TestCase):
    """R21-SEC-02 / R21-TECH-01: _run_git defensive environment variables."""

    def test_git_terminal_prompt_disabled(self):
        """_GIT_SAFE_ENV must set GIT_TERMINAL_PROMPT=0."""
        self.assertEqual(cli._GIT_SAFE_ENV.get("GIT_TERMINAL_PROMPT"), "0")

    def test_git_askpass_empty(self):
        """_GIT_SAFE_ENV must set GIT_ASKPASS to empty string."""
        self.assertEqual(cli._GIT_SAFE_ENV.get("GIT_ASKPASS"), "")

    def test_run_git_uses_no_optional_locks(self):
        """_run_git must pass --no-optional-locks to git."""
        import inspect

        src = inspect.getsource(cli._run_git)
        self.assertIn("--no-optional-locks", src)

    def test_hash_diff_streaming_uses_no_optional_locks(self):
        """_hash_diff_streaming must pass --no-optional-locks to git."""
        import inspect

        src = inspect.getsource(cli._hash_diff_streaming)
        self.assertIn("--no-optional-locks", src)

    def test_hash_diff_streaming_uses_safe_env(self):
        """_hash_diff_streaming must use _GIT_SAFE_ENV."""
        import inspect

        src = inspect.getsource(cli._hash_diff_streaming)
        self.assertIn("_GIT_SAFE_ENV", src)

    def test_run_git_uses_safe_env(self):
        """_run_git must use _GIT_SAFE_ENV."""
        import inspect

        src = inspect.getsource(cli._run_git)
        self.assertIn("_GIT_SAFE_ENV", src)


class TestSanitizeMdAmpersand(unittest.TestCase):
    """R11-SEC-01: _sanitize_md must escape & to prevent HTML entity bypass."""

    def test_ampersand_escaped(self):
        """Bare & must become &amp; in output."""
        result = cli._sanitize_md("A & B")
        self.assertIn("&amp;", result)
        self.assertNotIn("A & B", result)

    def test_pre_encoded_entity_neutralised(self):
        """&lt;script&gt; must NOT survive as-is (would be decoded by GFM)."""
        result = cli._sanitize_md("&lt;script&gt;")
        # The & should be escaped first, then < and > (but there are none)
        # So &lt; becomes &amp;lt; which GFM renders as literal '&lt;'
        self.assertIn("&amp;lt;", result)
        self.assertNotIn("&lt;script", result)  # Must not have raw entity

    def test_normal_html_still_escaped(self):
        """Real < and > must still be escaped to &lt; / &gt;."""
        result = cli._sanitize_md("<script>alert(1)</script>")
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;", result)
        self.assertIn("&gt;", result)

    def test_double_encoding_is_safe(self):
        """&amp; in input becomes &amp;amp; — safe and displays literally."""
        result = cli._sanitize_md("&amp;")
        self.assertEqual(result, "&amp;amp;")


class TestUnterminatedC1Strings(unittest.TestCase):
    """R11-SEC-02: _strip_terminal_escapes must strip unterminated C1 strings."""

    def test_unterminated_dcs_stripped(self):
        """DCS (ESC P) without ST should strip ESC P and payload."""
        text = "before\x1bPsome DCS payload without terminator"
        result = cli._strip_terminal_escapes(text)
        self.assertNotIn("DCS payload", result)
        self.assertIn("before", result)

    def test_unterminated_sos_stripped(self):
        """SOS (ESC X) without ST should strip ESC X and payload."""
        text = "start\x1bXSOS data no terminator"
        result = cli._strip_terminal_escapes(text)
        self.assertNotIn("SOS data", result)
        self.assertIn("start", result)

    def test_unterminated_pm_stripped(self):
        """PM (ESC ^) without ST should strip ESC ^ and payload."""
        text = "hello\x1b^secret PM data no terminator"
        result = cli._strip_terminal_escapes(text)
        self.assertNotIn("secret PM data", result)
        self.assertIn("hello", result)

    def test_terminated_still_works(self):
        """Properly terminated DCS should still be stripped."""
        text = "before\x1bPpayload\x1b\\after"
        result = cli._strip_terminal_escapes(text)
        self.assertNotIn("payload", result)
        self.assertIn("before", result)
        self.assertIn("after", result)


class TestDelAndC1Controls(unittest.TestCase):
    """R11-SEC-03: _strip_terminal_escapes must strip DEL and 8-bit C1 controls."""

    def test_del_stripped(self):
        """DEL (U+007F) must be removed from output."""
        text = "hello\x7fworld"
        result = cli._strip_terminal_escapes(text)
        self.assertEqual(result, "helloworld")

    def test_c1_csi_stripped(self):
        """U+009B (8-bit CSI) must be stripped."""
        text = "hello\u009bworld"
        result = cli._strip_terminal_escapes(text)
        self.assertEqual(result, "helloworld")

    def test_c1_dcs_stripped(self):
        """U+0090 (8-bit DCS) must be stripped."""
        text = "hello\u0090world"
        result = cli._strip_terminal_escapes(text)
        self.assertEqual(result, "helloworld")

    def test_c1_range_all_stripped(self):
        """All characters in U+0080–U+009F must be stripped."""
        text = "ok"
        for cp in range(0x80, 0xA0):
            text += chr(cp)
        text += "end"
        result = cli._strip_terminal_escapes(text)
        self.assertEqual(result, "okend")


class TestByteCountCap(unittest.TestCase):
    """R11-SEC-04: set_github_output value cap must use byte count."""

    def test_multibyte_value_byte_cap(self):
        """A value with multi-byte chars should be capped by byte size, not char count."""
        # Each emoji is 4 bytes in UTF-8
        emoji = "\U0001f600"  # 😀
        # 1M emojis = 1M chars but 4M bytes — should be rejected at 4MB byte cap
        big_value = emoji * (1024 * 1024)
        byte_size = len(big_value.encode("utf-8"))
        self.assertEqual(byte_size, 4 * 1024 * 1024)  # Exactly 4 MB bytes
        # At exactly 4 MB it should still be accepted
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            tmp = f.name
        try:
            with patch.dict(os.environ, {"GITHUB_OUTPUT": tmp}):
                cli.set_github_output("k", big_value)  # Should NOT raise
        finally:
            os.unlink(tmp)

    def test_multibyte_value_over_cap_rejected(self):
        """A value exceeding 4 MB in bytes should be rejected."""
        emoji = "\U0001f600"  # 4 bytes each
        big_value = emoji * (1024 * 1024 + 1)  # 4MB + 4 bytes
        with self.assertRaises(ValueError) as ctx:
            cli.set_github_output("k", big_value)
        self.assertIn("too large", str(ctx.exception))


class TestOverflowError(unittest.TestCase):
    """R11-TECH-01: format_receipt_pretty must catch OverflowError from inf."""

    def test_files_changed_infinity_coerced(self):
        """files_changed as float('inf') must be coerced to 0, not crash."""
        receipt = {
            "receipt_id": "g1-test",
            "content_hash": "sha256:abc",
            "timestamp": "2026-01-01T00:00:00Z",
            "commit": {
                "sha": "deadbeefcafe",
                "subject": "test",
                "author": {"name": "T", "email": "t@t"},
                "files_changed": float("inf"),
            },
            "ai_attestation": {"is_ai_authored": False, "signals_detected": []},
        }
        output = cli.format_receipt_pretty(receipt)
        self.assertIn("0 changed", output)

    def test_files_changed_neg_infinity_coerced(self):
        """files_changed as -inf must also be coerced to 0."""
        receipt = {
            "receipt_id": "g1-test",
            "content_hash": "sha256:abc",
            "timestamp": "2026-01-01T00:00:00Z",
            "commit": {
                "sha": "deadbeefcafe",
                "subject": "test",
                "author": {"name": "T", "email": "t@t"},
                "files_changed": float("-inf"),
            },
            "ai_attestation": {"is_ai_authored": False, "signals_detected": []},
        }
        output = cli.format_receipt_pretty(receipt)
        self.assertIn("0 changed", output)


class TestDeadParameter(unittest.TestCase):
    """R11-PUB-01: _check_json_depth must not have dead _current parameter."""

    def test_no_current_parameter(self):
        """_check_json_depth signature should not include _current."""
        import inspect

        sig = inspect.signature(cli._check_json_depth)
        self.assertNotIn("_current", sig.parameters)

    def test_still_works_with_two_args(self):
        """Function should still accept (obj, max_depth) positional args."""
        cli._check_json_depth({"a": 1}, 64)  # Should not raise


class TestSanitizeMdEmphasis(unittest.TestCase):
    """R12-SEC-01: _sanitize_md must escape GFM emphasis/strikethrough markers."""

    def test_asterisk_escaped(self):
        """Single asterisks (*bold*) must be escaped to prevent bold injection."""
        result = cli._sanitize_md("*bold*")
        self.assertNotIn("*", result.replace("\\*", ""))
        self.assertIn("\\*", result)

    def test_double_asterisk_escaped(self):
        """Double asterisks (**bold**) must also be escaped."""
        result = cli._sanitize_md("**strong**")
        self.assertNotIn("**", result.replace("\\*", ""))

    def test_underscore_escaped(self):
        """Underscores (_italic_) must be escaped to prevent italic injection."""
        result = cli._sanitize_md("_italic_")
        self.assertNotIn("_", result.replace("\\_", ""))
        self.assertIn("\\_", result)

    def test_tilde_escaped(self):
        """Tildes (~~strike~~) must be escaped to prevent strikethrough injection."""
        result = cli._sanitize_md("~~strikethrough~~")
        self.assertNotIn("~", result.replace("\\~", ""))
        self.assertIn("\\~", result)

    def test_combined_emphasis_all_escaped(self):
        """All emphasis markers in a single string must be escaped."""
        result = cli._sanitize_md("*bold* _italic_ ~~strike~~")
        # No unescaped emphasis markers
        cleaned = result.replace("\\*", "").replace("\\_", "").replace("\\~", "")
        self.assertNotIn("*", cleaned)
        self.assertNotIn("_", cleaned)
        self.assertNotIn("~", cleaned)

    def test_emphasis_in_github_summary(self):
        """Emphasis markers in commit subjects must not render in summary table."""
        receipts = [
            {
                "commit": {"sha": "abc123", "subject": "*bold* _italic_ ~~strike~~"},
                "ai_attestation": {"is_ai_authored": False, "signals_detected": []},
                "receipt_id": "g1-test",
            }
        ]
        result = cli.format_github_summary(receipts)
        # In the data row, emphasis markers should be escaped
        for line in result.split("\n"):
            if line.startswith("| ") and "Commit" not in line and "---" not in line:
                # No unescaped * _ ~ in data rows
                cleaned = line.replace("\\*", "").replace("\\_", "").replace("\\~", "")
                self.assertNotIn("*bold*", cleaned)
                self.assertNotIn("_italic_", cleaned)


class TestShaValidation(unittest.TestCase):
    """R12-SEC-03: get_commit_info must validate SHA format from git."""

    @patch("aiir._detect._run_git")
    def test_valid_sha1_accepted(self, mock_git):
        """A standard 40-hex SHA-1 should pass validation."""
        sha = "a" * 40
        fmt_line = f"{sha}\x00Author\x00a@e\x00date\x00CN\x00c@e\x00date\x00subject"
        mock_git.side_effect = [
            fmt_line + "\n",  # git log --format
            "body\n",  # git log --format=%B
            "parent\n",  # git rev-parse --verify
            "stat\n",  # git diff --stat
            "",  # git diff --name-only
        ]
        with patch("aiir._detect._hash_diff_streaming", return_value="sha256:abc"):
            info = cli.get_commit_info("HEAD")
        self.assertEqual(info.sha, sha)

    @patch("aiir._detect._run_git")
    def test_valid_sha256_accepted(self, mock_git):
        """A 64-hex SHA-256 hash should also pass validation."""
        sha = "b" * 64
        fmt_line = f"{sha}\x00Author\x00a@e\x00date\x00CN\x00c@e\x00date\x00subject"
        mock_git.side_effect = [
            fmt_line + "\n",
            "body\n",
            "parent\n",
            "stat\n",
            "",
        ]
        with patch("aiir._detect._hash_diff_streaming", return_value="sha256:abc"):
            info = cli.get_commit_info("HEAD")
        self.assertEqual(info.sha, sha)

    @patch("aiir._detect._run_git")
    def test_malformed_sha_rejected(self, mock_git):
        """A non-hex SHA should raise ValueError."""
        sha = "ZZZZ_not_a_sha_at_all_padding_padding_pa"
        fmt_line = f"{sha}\x00Author\x00a@e\x00date\x00CN\x00c@e\x00date\x00subject"
        mock_git.return_value = fmt_line + "\n"
        with self.assertRaises(ValueError) as ctx:
            cli.get_commit_info("HEAD")
        self.assertIn("Invalid commit SHA format", str(ctx.exception))

    @patch("aiir._detect._run_git")
    def test_short_sha_rejected(self, mock_git):
        """A SHA shorter than 40 chars should raise ValueError."""
        sha = "abcdef1234"  # only 10 chars
        fmt_line = f"{sha}\x00Author\x00a@e\x00date\x00CN\x00c@e\x00date\x00subject"
        mock_git.return_value = fmt_line + "\n"
        with self.assertRaises(ValueError) as ctx:
            cli.get_commit_info("HEAD")
        self.assertIn("Invalid commit SHA format", str(ctx.exception))


class TestPrettySignalsGuard(unittest.TestCase):
    """R13-TECH-01: format_receipt_pretty must handle non-list signals_detected."""

    def _make_receipt(self, signals):
        return {
            "commit": {
                "sha": "abc123",
                "subject": "test",
                "author": {"name": "A", "email": "a@e"},
                "files_changed": 1,
            },
            "ai_attestation": {"is_ai_authored": True, "signals_detected": signals},
            "receipt_id": "g1-test",
            "content_hash": "sha256:abc",
            "timestamp": "2026-01-01T00:00:00Z",
        }

    def test_dict_signals_no_crash(self):
        """signals_detected as dict should not crash (TypeError on dict[:3])."""
        receipt = self._make_receipt({"key": "val"})
        # Should not raise TypeError
        result = cli.format_receipt_pretty(receipt)
        self.assertIn("Receipt:", result)

    def test_string_signals_no_crash(self):
        """signals_detected as string should not crash."""
        receipt = self._make_receipt("some_signal")
        result = cli.format_receipt_pretty(receipt)
        self.assertIn("Receipt:", result)

    def test_none_signals_no_crash(self):
        """signals_detected as None should not crash."""
        receipt = self._make_receipt(None)
        result = cli.format_receipt_pretty(receipt)
        self.assertIn("Receipt:", result)

    def test_int_signals_no_crash(self):
        """signals_detected as int should not crash."""
        receipt = self._make_receipt(42)
        result = cli.format_receipt_pretty(receipt)
        self.assertIn("Receipt:", result)


class TestPrettyAuthorGuard(unittest.TestCase):
    """R15-SEC-01: format_receipt_pretty must handle non-dict author field."""

    def _make_receipt(self, author_val):
        return {
            "receipt_id": "g1-test",
            "content_hash": "sha256:abc",
            "timestamp": "2026-01-01T00:00:00Z",
            "commit": {
                "sha": "abc123",
                "subject": "test",
                "author": author_val,
                "files_changed": 1,
            },
            "ai_attestation": {"is_ai_authored": False, "signals_detected": []},
        }

    def test_author_string_no_crash(self):
        """author='not-a-dict' must not crash with AttributeError."""
        receipt = self._make_receipt("not-a-dict")
        result = cli.format_receipt_pretty(receipt)
        self.assertIn("Receipt", result)

    def test_author_list_no_crash(self):
        """author=[1, 2] must not crash."""
        receipt = self._make_receipt([1, 2])
        result = cli.format_receipt_pretty(receipt)
        self.assertIn("Receipt", result)

    def test_author_none_no_crash(self):
        """author=None must not crash."""
        receipt = self._make_receipt(None)
        result = cli.format_receipt_pretty(receipt)
        self.assertIn("Receipt", result)

    def test_author_int_no_crash(self):
        """author=42 must not crash."""
        receipt = self._make_receipt(42)
        result = cli.format_receipt_pretty(receipt)
        self.assertIn("Receipt", result)


class TestPrettyAndSummaryGuard(unittest.TestCase):
    """R14-SEC-02: format_receipt_pretty/summary must handle non-dict nested fields."""

    def test_pretty_non_dict_commit(self):
        """format_receipt_pretty must not crash when commit is a string."""
        receipt = {
            "receipt_id": "g1-test",
            "content_hash": "sha256:abc",
            "timestamp": "2026-01-01T00:00:00Z",
            "commit": "not-a-dict",
            "ai_attestation": {"is_ai_authored": False, "signals_detected": []},
        }
        result = cli.format_receipt_pretty(receipt)
        self.assertIn("Receipt", result)

    def test_pretty_non_dict_ai(self):
        """format_receipt_pretty must not crash when ai_attestation is a list."""
        receipt = {
            "receipt_id": "g1-test",
            "content_hash": "sha256:abc",
            "timestamp": "2026-01-01T00:00:00Z",
            "commit": {
                "sha": "abc123",
                "subject": "test",
                "author": {"name": "T", "email": "t@t"},
                "files_changed": 1,
            },
            "ai_attestation": [1, 2, 3],
        }
        result = cli.format_receipt_pretty(receipt)
        self.assertIn("Receipt", result)

    def test_summary_non_dict_commit(self):
        """format_github_summary must not crash when commit is an int."""
        receipts = [
            {
                "receipt_id": "g1-test",
                "commit": 42,
                "ai_attestation": {"is_ai_authored": False},
            }
        ]
        result = cli.format_github_summary(receipts)
        self.assertIn("AIIR Receipt Summary", result)

    def test_summary_non_dict_ai(self):
        """format_github_summary must not crash when ai_attestation is a string."""
        receipts = [
            {
                "receipt_id": "g1-test",
                "commit": {"sha": "abcdef1234567890", "subject": "test"},
                "ai_attestation": "not-a-dict",
            }
        ]
        result = cli.format_github_summary(receipts)
        self.assertIn("AIIR Receipt Summary", result)


class TestWriteReceiptShaSanitize(unittest.TestCase):
    """R15-SEC-02: write_receipt must sanitize SHA in filename."""

    def test_sha_with_slash_sanitized(self):
        """SHA containing '/' must have it replaced to prevent path traversal."""
        receipt = {
            "commit": {"sha": "a/../../evil"},
            "receipt_id": "g1-test",
            "content_hash": "sha256:abc",
        }
        import tempfile

        with tempfile.TemporaryDirectory() as _tmpdir:
            tmpdir = os.path.realpath(_tmpdir)
            # write_receipt checks cwd, so we chdir temporarily
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                path = cli.write_receipt(receipt, output_dir="receipts")
                # The file should be INSIDE receipts/, not escaped
                self.assertTrue(path.startswith(os.path.join(tmpdir, "receipts")))
                # Filename should not contain '/'
                filename = os.path.basename(path)
                self.assertNotIn("/", filename)
            finally:
                os.chdir(old_cwd)

    def test_sha_with_dotdot_sanitized(self):
        """SHA containing '..' must have dots replaced to prevent traversal."""
        receipt = {
            "commit": {"sha": "a..b..c..d.."},
            "receipt_id": "g1-test",
            "content_hash": "sha256:abc",
        }
        import tempfile

        with tempfile.TemporaryDirectory() as _tmpdir:
            tmpdir = os.path.realpath(_tmpdir)
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                path = cli.write_receipt(receipt, output_dir="receipts")
                self.assertTrue(path.startswith(os.path.join(tmpdir, "receipts")))
                filename = os.path.basename(path)
                # Dots should be sanitized to underscores
                self.assertNotIn("..", filename.split("receipt_")[1].split("_")[0])
            finally:
                os.chdir(old_cwd)


class TestPipeCleanup(unittest.TestCase):
    """R12-TECH-01: _hash_diff_streaming must close stdout on all paths."""

    @patch("subprocess.Popen")
    def test_stdout_closed_on_timeout(self, mock_popen):
        """proc.stdout.close() must be called even when diff times out."""
        import io

        mock_stdout = unittest.mock.MagicMock(spec=io.BufferedReader)
        # read() blocks forever — simulates a stalled process
        mock_stdout.read.side_effect = lambda n: b"x" * n
        mock_proc = unittest.mock.MagicMock()
        mock_proc.stdout = mock_stdout
        mock_proc.returncode = -9
        mock_popen.return_value = mock_proc

        with patch("aiir._core.GIT_TIMEOUT", 0):  # instant timeout
            with self.assertRaises(RuntimeError):
                cli._hash_diff_streaming("parent", "sha")

        mock_stdout.close.assert_called()

    @patch("subprocess.Popen")
    def test_stdout_closed_on_io_error(self, mock_popen):
        """proc.stdout.close() must be called on IOError during read."""
        import io

        mock_stdout = unittest.mock.MagicMock(spec=io.BufferedReader)
        mock_stdout.read.side_effect = IOError("disk failure")
        mock_proc = unittest.mock.MagicMock()
        mock_proc.stdout = mock_stdout
        mock_popen.return_value = mock_proc

        with self.assertRaises(IOError):
            cli._hash_diff_streaming("parent", "sha")

        mock_stdout.close.assert_called()


class TestHashDiffWaitZombie(unittest.TestCase):
    """R13-TECH-02: _hash_diff_streaming must kill zombie on final wait timeout."""

    @patch("subprocess.Popen")
    def test_final_wait_timeout_kills_process(self, mock_popen):
        """If proc.wait(30) times out after stdout drain, proc must be killed."""
        import io

        mock_stdout = unittest.mock.MagicMock(spec=io.BufferedReader)
        # Normal read: return some data then EOF
        mock_stdout.read.side_effect = [b"data", b""]
        mock_proc = unittest.mock.MagicMock()
        mock_proc.stdout = mock_stdout
        # First wait (final) times out, second wait (after kill) succeeds
        mock_proc.wait.side_effect = [
            subprocess.TimeoutExpired("git", 30),  # final wait
            None,  # wait after kill
        ]
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        # The function should handle the timeout internally
        # After kill, returncode might be -9; we need to set it after kill
        def kill_side_effect():
            mock_proc.returncode = -9

        mock_proc.kill.side_effect = kill_side_effect
        # Reset wait to succeed after kill
        mock_proc.wait.side_effect = [
            subprocess.TimeoutExpired("git", 30),
            None,
        ]
        mock_proc.returncode = -9

        # R14-TECH-01: Cleanup kill after successful data read should NOT raise.
        # The hash is valid because the read loop completed (stdout reached EOF).
        result = cli._hash_diff_streaming("parent", "sha")
        self.assertTrue(result.startswith("sha256:"))
        mock_proc.kill.assert_called()


class TestHashDiffCleanupKill(unittest.TestCase):
    """R14-TECH-01: _hash_diff_streaming must return valid hash when killed for cleanup."""

    @patch("subprocess.Popen")
    def test_cleanup_kill_returns_valid_hash(self, mock_popen):
        """When final wait times out and process is killed, hash is still valid."""
        import io

        mock_stdout = unittest.mock.MagicMock(spec=io.BufferedReader)
        mock_stdout.read.side_effect = [b"some diff content", b""]
        mock_proc = unittest.mock.MagicMock()
        mock_proc.stdout = mock_stdout

        def kill_effect():
            mock_proc.returncode = -9

        mock_proc.kill.side_effect = kill_effect
        mock_proc.wait.side_effect = [
            subprocess.TimeoutExpired("git", 30),
            None,
        ]
        mock_proc.returncode = -9
        mock_popen.return_value = mock_proc

        result = cli._hash_diff_streaming("parent_sha", "child_sha")
        self.assertTrue(result.startswith("sha256:"))
        self.assertEqual(len(result), 7 + 64)
        mock_proc.kill.assert_called_once()


class TestCrossPlatformFchmod(unittest.TestCase):
    """Verify the _HAS_FCHMOD guard works on platforms without os.fchmod."""

    def test_has_fchmod_is_bool(self):
        """_HAS_FCHMOD should be a boolean."""
        self.assertIsInstance(cli._HAS_FCHMOD, bool)

    def test_write_receipt_without_fchmod(self):
        """write_receipt should succeed when os.fchmod is unavailable."""
        receipt = _make_test_receipt()
        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                os.chdir(tmpdir)
                out = os.path.join(tmpdir, "out")
                os.makedirs(out)
                with patch.object(cli, "_HAS_FCHMOD", False):
                    path = cli.write_receipt(receipt, output_dir=out)
                self.assertTrue(Path(path).exists())
                data = json.loads(Path(path).read_text())
                self.assertEqual(data["receipt_id"], receipt["receipt_id"])
            finally:
                os.chdir(old_cwd)

    def test_save_config_without_fchmod(self):
        """_save_config should succeed when os.fchmod is unavailable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            config = {"instance_id": "test-id", "created": "2026-01-01T00:00:00Z"}
            with patch.object(cli, "_HAS_FCHMOD", False):
                cli._save_config(cfg_path, config)
            self.assertTrue(cfg_path.exists())
            data = json.loads(cfg_path.read_text())
            self.assertEqual(data["instance_id"], "test-id")

    def test_save_index_without_fchmod(self):
        """_save_index should succeed when os.fchmod is unavailable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            idx_path = Path(tmpdir) / "index.json"
            index = {
                "version": 1,
                "receipt_count": 0,
                "ai_commit_count": 0,
                "ai_percentage": 0.0,
                "first_receipt": None,
                "latest_timestamp": None,
                "unique_authors": 0,
                "commits": {},
            }
            with patch.object(cli, "_HAS_FCHMOD", False):
                cli._save_index(idx_path, index)
            self.assertTrue(idx_path.exists())
            data = json.loads(idx_path.read_text())
            self.assertEqual(data["version"], 1)

    def test_ledger_append_without_fchmod(self):
        """append_to_ledger should succeed when os.fchmod is unavailable."""
        receipt = _make_test_receipt()
        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                with patch.object(cli, "_HAS_FCHMOD", False):
                    appended, skipped, path = cli.append_to_ledger([receipt])
                self.assertEqual(appended, 1)
                self.assertTrue(Path(path).exists())
            finally:
                os.chdir(old_cwd)


class TestCrossPlatformPaths(unittest.TestCase):
    """Verify pathlib usage works across OS path conventions."""

    def test_ledger_paths_use_pathlib(self):
        """_ledger_paths should return Path objects, not strings."""
        dir_path, ledger_path, index_path = cli._ledger_paths()
        self.assertIsInstance(dir_path, Path)
        self.assertIsInstance(ledger_path, Path)
        self.assertIsInstance(index_path, Path)

    def test_config_path_uses_pathlib(self):
        """_config_path should return a Path object."""
        result = cli._config_path()
        self.assertIsInstance(result, Path)

    def test_write_receipt_handles_trailing_separator(self):
        """Output dir with trailing separator should work."""
        receipt = _make_test_receipt()
        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                os.chdir(tmpdir)
                out = os.path.join(tmpdir, "out")
                os.makedirs(out)
                # Add trailing separator (/ on POSIX, \\ on Windows)
                dir_with_sep = out + os.sep
                path = cli.write_receipt(receipt, output_dir=dir_with_sep)
                self.assertTrue(Path(path).exists())
            finally:
                os.chdir(old_cwd)

    def test_canonical_json_deterministic(self):
        """Canonical JSON must be byte-identical across platforms."""
        obj = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
        result1 = cli._canonical_json(obj)
        result2 = cli._canonical_json(obj)
        self.assertEqual(result1, result2)
        # Keys must be sorted
        self.assertIn('"a"', result1)
        idx_a = result1.index('"a"')
        idx_z = result1.index('"z"')
        self.assertLess(idx_a, idx_z, "Keys should be sorted")
        # No whitespace between separators
        self.assertNotIn(": ", result1)
        self.assertNotIn(", ", result1)

    def test_receipt_id_deterministic_across_calls(self):
        """Same input must produce same receipt_id every time."""
        commit = cli.CommitInfo(
            sha="abc123def456",
            author_name="Test",
            author_email="t@t.com",
            author_date="2026-01-01T00:00:00Z",
            committer_name="Test",
            committer_email="t@t.com",
            committer_date="2026-01-01T00:00:00Z",
            subject="test",
            body="test\n",
            diff_stat="1 file changed",
            diff_hash="sha256:aaa",
            files_changed=["f.py"],
            is_ai_authored=True,
            ai_signals_detected=["copilot"],
        )
        with patch.object(cli, "_run_git", return_value="https://example.com/repo"):
            r1 = cli.build_commit_receipt(commit)
            r2 = cli.build_commit_receipt(commit)
        self.assertEqual(r1["receipt_id"], r2["receipt_id"])
        self.assertEqual(r1["content_hash"], r2["content_hash"])


class TestCrossPlatformEncoding(unittest.TestCase):
    """Verify UTF-8 handling across platforms."""

    def test_ledger_writes_utf8(self):
        """Ledger should handle non-ASCII author names."""
        commit = cli.CommitInfo(
            sha="utf8test123456",
            author_name="Ñoño 日本語",
            author_email="intl@test.com",
            author_date="2026-01-01T00:00:00Z",
            committer_name="Ñoño",
            committer_email="intl@test.com",
            committer_date="2026-01-01T00:00:00Z",
            subject="intl: unicode test",
            body="intl: unicode test\n",
            diff_stat="1 file changed",
            diff_hash="sha256:bbb",
            files_changed=["ñ.py"],
            is_ai_authored=False,
            ai_signals_detected=[],
        )
        with patch.object(cli, "_run_git", return_value="https://example.com/repo"):
            receipt = cli.build_commit_receipt(commit)
        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                appended, _, path = cli.append_to_ledger([receipt])
                self.assertEqual(appended, 1)
                content = Path(path).read_text(encoding="utf-8")
                # Canonical JSON uses ensure_ascii — check via round-trip
                parsed = json.loads(content)
                self.assertEqual(parsed["commit"]["author"]["name"], "Ñoño 日本語")
                self.assertIn("ñ.py", parsed["commit"]["files"])
            finally:
                os.chdir(old_cwd)

    def test_export_preserves_unicode(self):
        """Export bundle should preserve non-ASCII data."""
        commit = cli.CommitInfo(
            sha="exportutf8test1",
            author_name="André",
            author_email="a@test.com",
            author_date="2026-01-01T00:00:00Z",
            committer_name="André",
            committer_email="a@test.com",
            committer_date="2026-01-01T00:00:00Z",
            subject="feat: café",
            body="feat: café\n",
            diff_stat="1 file changed",
            diff_hash="sha256:ccc",
            files_changed=["café.py"],
            is_ai_authored=True,
            ai_signals_detected=["copilot"],
        )
        with patch.object(cli, "_run_git", return_value="https://example.com/repo"):
            receipt = cli.build_commit_receipt(commit)
        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                cli.append_to_ledger([receipt])
                bundle = cli.export_ledger()
                self.assertIn("André", json.dumps(bundle, ensure_ascii=False))
            finally:
                os.chdir(old_cwd)

    def test_config_roundtrip_unicode_namespace(self):
        """Config should preserve unicode namespace values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            config = {
                "instance_id": str(uuid.uuid4()),
                "namespace": "société-générale",
                "created": "2026-01-01T00:00:00Z",
            }
            cli._save_config(cfg_path, config)
            loaded = json.loads(cfg_path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["namespace"], "société-générale")


class TestAtomicWriteSemantics(unittest.TestCase):
    """Verify atomic write pattern works on all platforms."""

    def test_save_config_uses_rename(self):
        """_save_config should leave no .tmp files behind."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            config = {"instance_id": "atomic-test", "created": "2026-01-01T00:00:00Z"}
            cli._save_config(cfg_path, config)
            # No .tmp file should remain
            tmp_files = list(Path(tmpdir).glob("*.tmp"))
            self.assertEqual(len(tmp_files), 0, f"Stale .tmp files found: {tmp_files}")
            self.assertTrue(cfg_path.exists())

    def test_save_index_uses_rename(self):
        """_save_index should leave no .tmp files behind."""
        with tempfile.TemporaryDirectory() as tmpdir:
            idx_path = Path(tmpdir) / "index.json"
            index = {
                "version": 1,
                "receipt_count": 5,
                "ai_commit_count": 2,
                "ai_percentage": 40.0,
                "first_receipt": "2026-01-01T00:00:00Z",
                "latest_timestamp": "2026-01-01T00:00:00Z",
                "unique_authors": 1,
                "commits": {},
            }
            cli._save_index(idx_path, index)
            tmp_files = list(Path(tmpdir).glob("*.tmp"))
            self.assertEqual(len(tmp_files), 0)
            self.assertTrue(idx_path.exists())
            self.assertEqual(json.loads(idx_path.read_text())["receipt_count"], 5)

    def test_overwrite_config_preserves_content(self):
        """Overwriting config should not corrupt data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            for i in range(5):
                config = {"instance_id": f"id-{i}", "created": "2026-01-01T00:00:00Z"}
                cli._save_config(cfg_path, config)
            final = json.loads(cfg_path.read_text())
            self.assertEqual(final["instance_id"], "id-4")


# Helper for cross-platform tests
def _make_test_receipt():
    """Create a minimal valid receipt for testing."""
    commit = cli.CommitInfo(
        sha="deadbeef12345678",
        author_name="Test User",
        author_email="test@example.com",
        author_date="2026-01-01T00:00:00Z",
        committer_name="Test User",
        committer_email="test@example.com",
        committer_date="2026-01-01T00:00:00Z",
        subject="test: cross-platform",
        body="test: cross-platform\n",
        diff_stat="1 file changed, 1 insertion(+)",
        diff_hash="sha256:0000",
        files_changed=["test.py"],
        is_ai_authored=False,
        ai_signals_detected=[],
    )
    with patch.object(cli, "_run_git", return_value="https://example.com/repo"):
        return cli.build_commit_receipt(commit)


class TestMultiReceiptJsonArray(unittest.TestCase):
    """R20-UX-03: Multiple receipts to stdout must be a valid JSON array."""

    def _make_receipt(self, sha_suffix="a"):
        """Build a minimal valid receipt for testing."""
        return {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "commit": {
                "sha": "abcdef1234567890" * 2 + sha_suffix * 8,
                "author": {"name": "A", "email": "a@b", "date": "2026-01-01T00:00:00Z"},
                "committer": {
                    "name": "A",
                    "email": "a@b",
                    "date": "2026-01-01T00:00:00Z",
                },
                "subject": "test",
                "message_hash": "sha256:0" * 64,
                "diff_hash": "sha256:0" * 64,
                "files_changed": 0,
                "files": [],
            },
            "ai_attestation": {
                "is_ai_authored": False,
                "signals_detected": [],
                "signal_count": 0,
                "detection_method": "heuristic_v1",
            },
            "provenance": {
                "repository": "",
                "tool": f"https://github.com/invariant-systems-ai/aiir@{cli.CLI_VERSION}",
                "generator": "aiir.cli",
            },
        }

    @patch("aiir.cli.get_repo_root", return_value="/fake")
    @patch("aiir.cli.generate_receipts_for_range")
    def test_multi_receipt_stdout_is_json_array(self, mock_gen, mock_root):
        """Two receipts to stdout must parse as a JSON list."""
        r1 = (
            cli.build_commit_receipt.__wrapped__(self._make_receipt("a")["commit"])
            if hasattr(cli.build_commit_receipt, "__wrapped__")
            else self._make_receipt("a")
        )
        r2 = self._make_receipt("b")
        mock_gen.return_value = [r1, r2]

        import io

        captured = io.StringIO()
        with (
            patch("sys.stdout", captured),
            patch("sys.argv", ["aiir", "--range", "HEAD~2..HEAD", "--quiet", "--json"]),
        ):
            cli.main()

        output = captured.getvalue()
        data = json.loads(output)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 2)

    @patch("aiir.cli.get_repo_root", return_value="/fake")
    @patch("aiir.cli.generate_receipt")
    def test_single_receipt_stdout_is_json_object(self, mock_gen, mock_root):
        """A single receipt with --json must parse as a JSON dict."""
        r = self._make_receipt("a")
        r["receipt_id"] = "g1-test"
        r["content_hash"] = "sha256:test"
        r["timestamp"] = "2026-01-01T00:00:00Z"
        mock_gen.return_value = r

        import io

        captured = io.StringIO()
        with (
            patch("sys.stdout", captured),
            patch("sys.argv", ["aiir", "--quiet", "--json"]),
        ):
            cli.main()

        output = captured.getvalue()
        data = json.loads(output)
        self.assertIsInstance(data, dict)
        self.assertEqual(data.get("type"), "aiir.commit_receipt")


class TestPrettyPlusOutput(unittest.TestCase):
    """R16-UX-01: --pretty and --output must work together — print pretty
    to stdout AND write receipt file to disk."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        subprocess.run(["git", "init", self.tmpdir], capture_output=True, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=self.tmpdir,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test User"],
            cwd=self.tmpdir,
            capture_output=True,
            check=True,
        )
        Path(self.tmpdir, "file.txt").write_text("hello")
        subprocess.run(
            ["git", "add", "."], cwd=self.tmpdir, capture_output=True, check=True
        )
        subprocess.run(
            ["git", "commit", "-m", "init"],
            cwd=self.tmpdir,
            capture_output=True,
            check=True,
        )

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_pretty_and_output_both_work(self):
        """R16-UX-01: --pretty --output should print pretty AND write file."""
        out_dir = os.path.join(self.tmpdir, ".receipts")
        old_cwd = os.getcwd()
        try:
            os.chdir(self.tmpdir)
            import io

            captured_err = io.StringIO()
            with patch("sys.stderr", captured_err), patch("sys.stdout", io.StringIO()):
                rc = cli.main(["--pretty", "--output", out_dir])
            self.assertEqual(rc, 0)
            # Pretty output should be on stderr
            stderr_text = captured_err.getvalue()
            self.assertIn(
                "┌", stderr_text, "Pretty box-drawing should appear on stderr"
            )
            # File should also be written to disk
            files = list(Path(out_dir).glob("receipt_*.json"))
            self.assertGreaterEqual(
                len(files), 1, "Receipt file must be written when --output is set"
            )
            # File content should be valid JSON
            content = files[0].read_text()
            receipt = json.loads(content)
            self.assertIn("commit", receipt)
        finally:
            os.chdir(old_cwd)

    def test_pretty_without_output_no_file(self):
        """--pretty alone prints to stderr and writes to .aiir/ ledger."""
        old_cwd = os.getcwd()
        try:
            os.chdir(self.tmpdir)
            import io

            captured_err = io.StringIO()
            with patch("sys.stderr", captured_err), patch("sys.stdout", io.StringIO()):
                rc = cli.main(["--pretty"])
            self.assertEqual(rc, 0)
            stderr_text = captured_err.getvalue()
            self.assertIn("┌", stderr_text)
            # Default mode creates .aiir/receipts.jsonl (ledger), not individual files
            receipt_files = list(Path(self.tmpdir).rglob("receipt_*.json"))
            self.assertEqual(
                len(receipt_files),
                0,
                "--pretty must not write individual receipt files",
            )
            # But the ledger should exist
            ledger = Path(self.tmpdir) / ".aiir" / "receipts.jsonl"
            self.assertTrue(
                ledger.exists(), "default mode should create .aiir/receipts.jsonl"
            )
        finally:
            os.chdir(old_cwd)

    def test_output_without_pretty_writes_file_only(self):
        """--output alone should write file, stdout gets JSON (not pretty)."""
        out_dir = os.path.join(self.tmpdir, ".receipts")
        old_cwd = os.getcwd()
        try:
            os.chdir(self.tmpdir)
            from io import StringIO

            captured = StringIO()
            with patch("sys.stdout", captured):
                rc = cli.main(["--output", out_dir])
            self.assertEqual(rc, 0)
            # File should be written
            files = list(Path(out_dir).glob("receipt_*.json"))
            self.assertGreaterEqual(len(files), 1)
            # stdout should NOT contain pretty box-drawing
            stdout_text = captured.getvalue()
            self.assertNotIn(
                "┌", stdout_text, "Box-drawing should not appear without --pretty"
            )
        finally:
            os.chdir(old_cwd)
