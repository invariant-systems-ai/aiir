"""Security hardening tests — differential GFM testing & source-code guards.

Gap 1: _sanitize_md differential tests against a real Markdown parser.
Gap 2: Source-code assertion that hmac.compare_digest is used for
       constant-time comparison (prevents accidental regression to ==).
"""

from __future__ import annotations

import ast
import inspect
import textwrap
import unittest

from aiir._core import _sanitize_md

# ---------------------------------------------------------------------------
# We use markdown-it-py as our reference GFM parser.  It ships with the
# GFM tables extension and produces predictable HTML output that we can
# inspect for dangerous constructs.
# ---------------------------------------------------------------------------
try:
    from markdown_it import MarkdownIt

    _MD = MarkdownIt("gfm-like")
    _HAS_MARKDOWN_IT = True
except ImportError:
    _HAS_MARKDOWN_IT = False


def _render(text: str) -> str:
    """Render sanitized text through markdown-it-py and return HTML."""
    assert _HAS_MARKDOWN_IT, "markdown-it-py is required for differential tests"
    return _MD.render(text)


def _render_in_table(cell_text: str) -> str:
    """Render *cell_text* inside a GFM table cell and return HTML."""
    table = f"| Header |\n|--------|\n| {cell_text} |"
    return _render(table)


# ═══════════════════════════════════════════════════════════════════════════
# Gap 1 — _sanitize_md differential tests (Covers: E-04, I-05)
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(_HAS_MARKDOWN_IT, "markdown-it-py not installed")
class TestSanitizeMdDifferentialHTML(unittest.TestCase):
    """Verify _sanitize_md output, when parsed by GFM, produces no raw HTML."""

    # -- Direct HTML injection attempts --

    def test_script_tag_neutralised(self):
        """<script> must not survive as a real HTML tag.  Covers: E-04"""
        raw = '<script>alert("xss")</script>'
        html = _render(_sanitize_md(raw))
        self.assertNotIn("<script", html.lower())

    def test_img_tag_onerror_neutralised(self):
        """<img onerror=...> must not render as HTML.  Covers: E-04"""
        raw = '<img src=x onerror="alert(1)">'
        html = _render(_sanitize_md(raw))
        self.assertNotIn("<img", html.lower())

    def test_iframe_neutralised(self):
        """<iframe> must not render.  Covers: E-04"""
        raw = '<iframe src="https://evil.com"></iframe>'
        html = _render(_sanitize_md(raw))
        self.assertNotIn("<iframe", html.lower())

    def test_svg_onload_neutralised(self):
        """<svg onload=...> must not render.  Covers: E-04"""
        raw = '<svg onload="alert(1)">'
        html = _render(_sanitize_md(raw))
        self.assertNotIn("<svg", html.lower())

    def test_details_tag_neutralised(self):
        """<details> (used in GFM) must not render as raw HTML.  Covers: E-04"""
        raw = "<details><summary>click me</summary>payload</details>"
        html = _render(_sanitize_md(raw))
        self.assertNotIn("<details", html.lower())

    def test_math_tag_neutralised(self):
        """<math> (MathML) must not render.  Covers: E-04"""
        raw = '<math><mtext>x</mtext></math>'
        html = _render(_sanitize_md(raw))
        self.assertNotIn("<math", html.lower())

    def test_style_tag_neutralised(self):
        """<style> must not render.  Covers: E-04"""
        raw = "<style>body{display:none}</style>"
        html = _render(_sanitize_md(raw))
        self.assertNotIn("<style", html.lower())

    def test_data_uri_neutralised(self):
        """data: URI in an anchor must not produce an active link.  Covers: E-04"""
        raw = '<a href="data:text/html,<h1>XSS</h1>">click</a>'
        html = _render(_sanitize_md(raw))
        # The <a> tag must NOT render as a real anchor element.
        # The text may appear literally (entity-encoded) but not as <a href=...>.
        self.assertNotRegex(html, r'<a\s+href=', msg="data: URI link survived")

    # -- Angle-bracket edge cases --

    def test_angle_bracket_entity_encoding(self):
        """Both < and > must be entity-encoded in output.  Covers: E-04"""
        sanitised = _sanitize_md("a < b > c")
        self.assertNotIn("<", sanitised.replace("&lt;", "").replace("&amp;", ""))
        self.assertNotIn(">", sanitised.replace("&gt;", "").replace("&amp;", ""))

    def test_nested_angle_brackets(self):
        """<<script>> double-nesting must be neutralised.  Covers: E-04"""
        html = _render(_sanitize_md("<<script>>alert(1)<</script>>"))
        self.assertNotIn("<script", html.lower())


@unittest.skipUnless(_HAS_MARKDOWN_IT, "markdown-it-py not installed")
class TestSanitizeMdDifferentialTable(unittest.TestCase):
    """Verify _sanitize_md output cannot break GFM table structure."""

    def test_pipe_in_cell_does_not_create_extra_column(self):
        """A literal | must not split into a second table column.  Covers: E-04"""
        html = _render_in_table(_sanitize_md("col1 | col2"))
        # The table should have exactly 1 data cell, not 2
        td_count = html.lower().count("<td>")
        self.assertEqual(td_count, 1, f"Expected 1 <td> but got {td_count}: {html}")

    def test_backslash_pipe_does_not_break_table(self):
        r"""The sequence \| must not become \\| and re-enable the pipe.  Covers: E-04"""
        html = _render_in_table(_sanitize_md("a\\|b"))
        td_count = html.lower().count("<td>")
        self.assertEqual(td_count, 1, f"Pipe escaped incorrectly: {html}")

    def test_multiple_pipes_in_cell(self):
        """Multiple pipes must all be escaped.  Covers: E-04"""
        html = _render_in_table(_sanitize_md("a|b|c|d"))
        td_count = html.lower().count("<td>")
        self.assertEqual(td_count, 1)


@unittest.skipUnless(_HAS_MARKDOWN_IT, "markdown-it-py not installed")
class TestSanitizeMdDifferentialEmphasis(unittest.TestCase):
    """Verify GFM emphasis/strikethrough markers are neutralised."""

    def test_bold_neutralised(self):
        """**bold** must render as literal asterisks, not <strong>.  Covers: E-04"""
        html = _render(_sanitize_md("**bold**"))
        self.assertNotIn("<strong", html.lower())
        self.assertNotIn("<em", html.lower())

    def test_italic_underscore_neutralised(self):
        """_italic_ must not produce <em>.  Covers: E-04"""
        html = _render(_sanitize_md("_italic_"))
        self.assertNotIn("<em", html.lower())

    def test_strikethrough_neutralised(self):
        """~~strike~~ must not produce <del>/<s>.  Covers: E-04"""
        html = _render(_sanitize_md("~~strike~~"))
        self.assertNotIn("<del", html.lower())
        self.assertNotIn("<s>", html.lower())

    def test_inline_code_neutralised(self):
        """`code` must not produce <code>.  Covers: E-04"""
        html = _render(_sanitize_md("`code`"))
        self.assertNotIn("<code", html.lower())


@unittest.skipUnless(_HAS_MARKDOWN_IT, "markdown-it-py not installed")
class TestSanitizeMdDifferentialLinks(unittest.TestCase):
    """Verify autolink and Markdown link syntax is broken."""

    def test_autolink_url_broken(self):
        """https://evil.com must not become a clickable <a>.  Covers: E-04, I-05"""
        html = _render(_sanitize_md("visit https://evil.com now"))
        # The URL should NOT be wrapped in <a href=...>
        self.assertNotRegex(html, r'<a\s+href=', msg="Autolink survived sanitization")

    def test_markdown_link_syntax_broken(self):
        """[text](url) must not produce a link.  Covers: E-04"""
        html = _render(_sanitize_md("[click here](https://evil.com)"))
        self.assertNotRegex(html, r'<a\s+href=')

    def test_image_syntax_broken(self):
        """![alt](url) must not produce an <img>.  Covers: E-04"""
        html = _render(_sanitize_md("![img](https://evil.com/x.png)"))
        self.assertNotIn("<img", html.lower())

    def test_reference_link_broken(self):
        """[text][ref] reference links must not render.  Covers: E-04"""
        text = _sanitize_md("[click][evil]\n\n[evil]: https://evil.com")
        html = _render(text)
        self.assertNotRegex(html, r'<a\s+href=')


@unittest.skipUnless(_HAS_MARKDOWN_IT, "markdown-it-py not installed")
class TestSanitizeMdDifferentialUnicode(unittest.TestCase):
    """Verify dangerous Unicode is stripped before GFM rendering."""

    def test_bidi_override_stripped(self):
        """RTL/LTR overrides must be removed.  Covers: S-01, I-05"""
        for cp in ["\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
                    "\u2066", "\u2067", "\u2068", "\u2069"]:
            result = _sanitize_md(f"safe{cp}text")
            self.assertNotIn(cp, result, f"Bidi codepoint U+{ord(cp):04X} survived")

    def test_zwj_zwnj_stripped(self):
        """ZWJ/ZWNJ used for homoglyph attacks must be stripped.  Covers: S-01, S-02"""
        for cp in ["\u200c", "\u200d"]:
            result = _sanitize_md(f"co{cp}pilot")
            self.assertNotIn(cp, result)

    def test_soft_hyphen_stripped(self):
        """Soft hyphen (U+00AD) must be stripped.  Covers: S-01"""
        result = _sanitize_md("co\u00adpilot")
        self.assertNotIn("\u00ad", result)

    def test_bom_stripped(self):
        """BOM / ZWNBSP must be stripped.  Covers: S-01"""
        result = _sanitize_md("\ufeffhello")
        self.assertNotIn("\ufeff", result)

    def test_c0_control_chars_stripped(self):
        """C0 control characters (except \\n, \\r, \\t?) must be stripped.  Covers: E-05"""
        # Test BEL, ESC, NUL, etc.
        for i in [0, 1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 16, 17, 18, 19,
                  20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]:
            c = chr(i)
            result = _sanitize_md(f"a{c}b")
            self.assertNotIn(c, result, f"Control char U+{i:04X} survived")


@unittest.skipUnless(_HAS_MARKDOWN_IT, "markdown-it-py not installed")
class TestSanitizeMdDifferentialComposed(unittest.TestCase):
    """Composed adversarial payloads combining multiple attack vectors."""

    def test_polyglot_xss_payload(self):
        """Classic polyglot XSS must be fully neutralised.  Covers: E-04"""
        payload = "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e"
        html = _render(_sanitize_md(payload))
        # Real HTML elements must not be created — check for actual tags, not
        # literal text in entity-encoded output.
        self.assertNotRegex(html, r'<svg[\s/>]', msg="<svg> survived as real tag")
        self.assertNotRegex(html, r'<script[\s/>]', msg="<script> survived as real tag")
        # Event handlers must not appear in actual HTML attributes
        self.assertNotRegex(html, r'\bon\w+=', msg="Event handler survived in HTML attribute")

    def test_table_breakout_with_html(self):
        """Pipe + HTML injection must not break table AND inject HTML.  Covers: E-04"""
        payload = 'safe | <img src=x onerror=alert(1)>'
        html = _render_in_table(_sanitize_md(payload))
        self.assertNotIn("<img", html.lower())
        td_count = html.lower().count("<td>")
        self.assertEqual(td_count, 1)

    def test_backslash_chain_escape_attempt(self):
        r"""Long backslash chains must not break the escaping logic.  Covers: E-04"""
        payload = "\\\\" * 50 + "|" + "<script>alert(1)</script>"
        sanitised = _sanitize_md(payload)
        html = _render(sanitised)
        self.assertNotIn("<script", html.lower())

    def test_entity_double_encoding_safe(self):
        """Pre-encoded &lt;script&gt; must not decode back to <script>.  Covers: E-04"""
        payload = "&lt;script&gt;alert(1)&lt;/script&gt;"
        html = _render(_sanitize_md(payload))
        self.assertNotIn("<script", html.lower())

    def test_null_byte_injection(self):
        """Null bytes must be stripped — they can truncate parsers.  Covers: E-05"""
        result = _sanitize_md("safe\x00<script>")
        self.assertNotIn("\x00", result)
        html = _render(result)
        self.assertNotIn("<script", html.lower())


# ═══════════════════════════════════════════════════════════════════════════
# Gap 2 — hmac.compare_digest source-code guard (Covers: T-01, T-02)
# ═══════════════════════════════════════════════════════════════════════════


class TestConstantTimeComparisonGuard(unittest.TestCase):
    """Source-code inspection: verify_receipt MUST use hmac.compare_digest
    for hash and receipt_id comparison, and MUST NOT use == or != on
    security-sensitive values.

    This test inspects the AST of _verify.py to prevent accidental
    regression from constant-time comparison to simple equality.
    """

    def _get_verify_source(self) -> str:
        """Return the source code of the verify_receipt function."""
        from aiir._verify import verify_receipt
        return inspect.getsource(verify_receipt)

    def test_hmac_compare_digest_present(self):
        """verify_receipt MUST call hmac.compare_digest.  Covers: T-01"""
        source = self._get_verify_source()
        self.assertIn("hmac.compare_digest", source,
                       "verify_receipt must use hmac.compare_digest for constant-time comparison")

    def test_hmac_compare_digest_used_for_hash(self):
        """Stored hash comparison MUST use hmac.compare_digest.  Covers: T-01"""
        source = self._get_verify_source()
        # The hash comparison should pass stored_hash and expected_hash
        self.assertIn("stored_hash", source)
        self.assertIn("expected_hash", source)
        # Ensure hmac.compare_digest is used (at least 2 calls: hash + id)
        count = source.count("hmac.compare_digest")
        self.assertGreaterEqual(count, 2,
                                f"Expected ≥2 hmac.compare_digest calls, found {count}")

    def test_no_equality_operator_on_hashes(self):
        """Hash/id comparisons MUST NOT use == or !=.  Covers: T-01, T-02"""
        source = self._get_verify_source()
        tree = ast.parse(textwrap.dedent(source))

        # Collect all Compare nodes that use == or != with hash/id variables
        dangerous_comparisons = []
        sensitive_names = {"stored_hash", "expected_hash", "stored_id", "expected_id",
                          "hash_ok", "id_ok"}

        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            # Check if any comparator involves a sensitive variable
            all_nodes = [node.left] + node.comparators
            involved_names = set()
            for n in all_nodes:
                if isinstance(n, ast.Name) and n.id in sensitive_names:
                    involved_names.add(n.id)
            if not involved_names:
                continue
            # Check if any operator is Eq or NotEq
            for op in node.ops:
                if isinstance(op, (ast.Eq, ast.NotEq)):
                    dangerous_comparisons.append(
                        f"Line ~{node.lineno}: {ast.dump(node)} uses ==/!= on {involved_names}"
                    )

        self.assertEqual(dangerous_comparisons, [],
                         "Dangerous equality on security-sensitive values:\n"
                         + "\n".join(dangerous_comparisons))

    def test_hmac_import_present(self):
        """The hmac module MUST be imported in _verify.py.  Covers: T-01"""
        import aiir._verify as verify_mod
        source = inspect.getsource(verify_mod)
        self.assertIn("import hmac", source,
                       "_verify.py must import hmac for constant-time comparison")

    def test_compare_digest_not_wrapped_in_equality(self):
        """hmac.compare_digest result must not be compared with == True.  Covers: T-01"""
        source = self._get_verify_source()
        # Patterns like `if hmac.compare_digest(...) == True:` are redundant
        # but not dangerous — however `== False` would invert the logic.
        self.assertNotIn("compare_digest(", source.replace(" ", "").split("==False")[0]
                         if "==False" in source.replace(" ", "") else "SKIP_CHECK",
                         "hmac.compare_digest result must not be compared with == False")
        # Simpler check: no `== False` or `!= True` near compare_digest
        for line in source.splitlines():
            if "compare_digest" in line:
                self.assertNotIn("== False", line)
                self.assertNotIn("!= True", line)


if __name__ == "__main__":
    unittest.main()
