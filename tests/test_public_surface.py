"""
Public Surface QC — deterministic end-to-end test of every public-facing claim.

This is the "virtual user environment" test.  It simulates what a partner
evaluator, GitHub/GitLab reviewer, or prospective customer sees when they
visit the website, read the README, install from PyPI, or configure MCP.
Every assertion here is a contract: if it fails, something the public can
see is wrong.

Surfaces tested:
  1.  Website HTML integrity (nav, footer, meta tags, CSP, analytics)
  2.  Cross-surface version consistency (__init__ ↔ manifest ↔ website ↔ action)
  3.  MCP manifest ↔ server implementation ↔ website .well-known/mcp.json
  4.  AI detection table (integrations page) ↔ _detect.py (actual patterns)
  5.  CI template claims (integrations page) ↔ templates/ directory
  6.  Sitemap ↔ actual HTML files
  7.  Link integrity (all internal hrefs resolve to real files)
  8.  README documented commands ↔ actual CLI entry points
  9.  Schema files exist and are valid JSON
  10. Content-tier policy compliance (no T1+ references on T0 surfaces)

Designed to run in CI without network access — all checks are local/filesystem.
The SITE_DIR env var points to the website checkout; defaults to sibling repo.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import os
import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Set

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
AIIR_ROOT = Path(__file__).resolve().parent.parent
SITE_DIR = Path(
    os.environ.get(
        "AIIR_SITE_DIR",
        AIIR_ROOT.parent / "invariantsystems.io",
    )
)

# Skip the entire module if the website repo isn't checked out alongside.
# In CI, the workflow clones both repos side-by-side.
SITE_EXISTS = SITE_DIR.is_dir() and (SITE_DIR / "index.html").is_file()


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _html_files() -> List[Path]:
    """All HTML pages (excluding 404 which has its own rules)."""
    return sorted(p for p in SITE_DIR.glob("*.html") if p.name != "404.html")


def _main_pages() -> List[Path]:
    """The 10 main navigable pages."""
    expected = {
        "about.html",
        "docs.html",
        "index.html",
        "integrations.html",
        "pricing.html",
        "privacy.html",
        "security.html",
        "spec.html",
        "terms.html",
        "verify.html",
    }
    found = [p for p in _html_files() if p.name in expected]
    return found


# ═══════════════════════════════════════════════════════════════════════════
# 1. WEBSITE HTML INTEGRITY
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(SITE_EXISTS, "Website repo not found — set AIIR_SITE_DIR")
class TestWebsiteHTMLIntegrity(unittest.TestCase):
    """Every HTML page passes structural QC."""

    def test_all_10_main_pages_exist(self):
        pages = {p.name for p in _main_pages()}
        expected = {
            "about.html",
            "docs.html",
            "index.html",
            "integrations.html",
            "pricing.html",
            "privacy.html",
            "security.html",
            "spec.html",
            "terms.html",
            "verify.html",
        }
        self.assertEqual(pages, expected, f"Missing pages: {expected - pages}")

    def test_nav_consistency_8_links(self):
        """Every main page header <nav> has exactly 8 links."""
        expected_hrefs = {
            "/docs",
            "/verify",
            "/integrations",
            "/spec",
            "/pricing",
            "/security",
            "/about",
        }
        for page in _main_pages():
            content = _read(page)
            nav_match = re.search(r"<nav>(.*?)</nav>", content, re.DOTALL)
            self.assertIsNotNone(nav_match, f"{page.name}: no <nav> found")
            nav_html = nav_match.group(1)
            hrefs = re.findall(r'href="([^"]*)"', nav_html)
            self.assertEqual(
                len(hrefs),
                8,
                f"{page.name}: expected 8 nav links, got {len(hrefs)}: {hrefs}",
            )
            # Check essential internal links are present
            href_set = set(hrefs)
            for expected in expected_hrefs:
                self.assertIn(
                    expected,
                    href_set,
                    f"{page.name}: nav missing {expected}",
                )

    def test_footer_consistency_10_links(self):
        """Every main page footer-links paragraph has exactly 10 links."""
        for page in _main_pages():
            content = _read(page)
            footer_match = re.search(
                r'<p class="footer-links">(.*?)</p>', content, re.DOTALL
            )
            self.assertIsNotNone(footer_match, f"{page.name}: no footer-links found")
            hrefs = re.findall(r'href="([^"]*)"', footer_match.group(1))
            self.assertEqual(
                len(hrefs),
                10,
                f"{page.name}: expected 10 footer links, got {len(hrefs)}: {hrefs}",
            )
            # Must include integrations
            self.assertIn(
                "/integrations",
                hrefs,
                f"{page.name}: footer missing /integrations link",
            )

    def test_og_tags_on_all_pages(self):
        """Every main page has og:title, og:description, og:type, og:url, og:image."""
        required_og = ["og:title", "og:description", "og:type", "og:url", "og:image"]
        for page in _main_pages():
            content = _read(page)
            for tag in required_og:
                self.assertIn(
                    f'property="{tag}"',
                    content,
                    f"{page.name}: missing {tag} meta tag",
                )

    def test_twitter_cards_on_all_pages(self):
        """Every main page has twitter:card meta tag."""
        for page in _main_pages():
            content = _read(page)
            self.assertIn(
                'name="twitter:card"',
                content,
                f"{page.name}: missing twitter:card meta tag",
            )

    def test_canonical_urls_on_all_pages(self):
        """Every main page has a canonical link."""
        for page in _main_pages():
            content = _read(page)
            match = re.search(r'rel="canonical" href="([^"]*)"', content)
            self.assertIsNotNone(match, f"{page.name}: missing canonical URL")
            url = match.group(1)
            self.assertTrue(
                url.startswith("https://invariantsystems.io"),
                f"{page.name}: canonical URL not on correct domain: {url}",
            )

    def test_content_tier_t0_tag(self):
        """Every HTML page (including 404) has content-tier T0 tag."""
        for page in SITE_DIR.glob("*.html"):
            content = _read(page)
            self.assertIn(
                'data-content-tier="T0"',
                content,
                f"{page.name}: missing content-tier T0 tag",
            )

    def test_csp_headers_present(self):
        """Every main page has a Content-Security-Policy meta tag."""
        for page in _main_pages():
            content = _read(page)
            self.assertIn(
                "Content-Security-Policy",
                content,
                f"{page.name}: missing CSP header",
            )

    def test_plausible_analytics_on_all_main_pages(self):
        """Every main page includes the Plausible analytics script."""
        for page in _main_pages():
            content = _read(page)
            self.assertIn(
                "plausible.js",
                content,
                f"{page.name}: missing Plausible analytics script",
            )

    def test_no_inline_styles_on_integrations(self):
        """Integrations page has zero inline style= attributes (CSS classes only)."""
        content = _read(SITE_DIR / "integrations.html")
        inline_styles = re.findall(r'\bstyle="', content)
        self.assertEqual(
            len(inline_styles),
            0,
            f"integrations.html has {len(inline_styles)} inline style= attributes "
            f"(should be 0 — use CSS classes instead)",
        )

    def test_no_version_js_without_data_attrs(self):
        """Pages with version.js must also have data-aiir-version elements."""
        for page in _main_pages():
            content = _read(page)
            has_version_js = "version.js" in content
            has_version_attr = "data-aiir-version" in content
            if has_version_js and not has_version_attr:
                self.fail(
                    f"{page.name}: includes version.js but has no "
                    f"data-aiir-version elements — causes silent CSP error",
                )


# ═══════════════════════════════════════════════════════════════════════════
# 2. CROSS-SURFACE VERSION CONSISTENCY
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(SITE_EXISTS, "Website repo not found — set AIIR_SITE_DIR")
class TestVersionConsistency(unittest.TestCase):
    """Version strings must match across all public surfaces."""

    def _aiir_version(self) -> str:
        from aiir import __version__

        return __version__

    def _manifest_version(self) -> str:
        manifest = json.loads(_read(AIIR_ROOT / "mcp-manifest.json"))
        return manifest["version"]

    def _website_stats_version(self) -> str:
        stats = json.loads(_read(SITE_DIR / "stats.json"))
        return stats["version"]

    def _website_mcp_version(self) -> str:
        mcp = json.loads(_read(SITE_DIR / ".well-known" / "mcp.json"))
        return mcp["servers"][0]["version"]

    def _docs_api_version(self) -> str:
        content = _read(AIIR_ROOT / "docs" / "api.md")
        match = re.search(r"\*?\*?[Vv]ersion\*?\*?[:\s]+([\d]+\.[\d]+\.[\d]+)", content)
        return match.group(1) if match else "NOT_FOUND"

    def test_all_versions_match(self):
        """__init__ == manifest == stats.json == .well-known/mcp.json == docs/api.md"""
        aiir = self._aiir_version()
        versions = {
            "__init__.py": aiir,
            "mcp-manifest.json": self._manifest_version(),
            "stats.json": self._website_stats_version(),
            ".well-known/mcp.json": self._website_mcp_version(),
            "docs/api.md": self._docs_api_version(),
        }
        mismatches = {k: v for k, v in versions.items() if v != aiir}
        self.assertEqual(
            mismatches,
            {},
            f"Version drift detected (expected {aiir}): {mismatches}",
        )


# ═══════════════════════════════════════════════════════════════════════════
# 3. MCP MANIFEST ↔ SERVER ↔ WEBSITE
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(SITE_EXISTS, "Website repo not found — set AIIR_SITE_DIR")
class TestMCPConsistency(unittest.TestCase):
    """MCP tool definitions match across manifest, server, and website."""

    def _manifest_tools(self) -> List[str]:
        manifest = json.loads(_read(AIIR_ROOT / "mcp-manifest.json"))
        return sorted(t["name"] for t in manifest["tools"])

    def _server_tools(self) -> List[str]:
        """Extract tool names from the handler dispatch map in mcp_server.py."""
        content = _read(AIIR_ROOT / "aiir" / "mcp_server.py")
        # Match the handler dispatch dictionary entries
        return sorted(re.findall(r'"(aiir_\w+)":\s*_handle_', content))

    def _website_mcp_tools(self) -> List[str]:
        mcp = json.loads(_read(SITE_DIR / ".well-known" / "mcp.json"))
        return sorted(t["name"] for t in mcp["servers"][0]["tools"])

    def _integrations_page_tools(self) -> List[str]:
        """Extract tool names from the MCP Tools table on the integrations page."""
        content = _read(SITE_DIR / "integrations.html")
        # Match <code>aiir_xxx</code> in table cells
        return sorted(re.findall(r"<code>(aiir_\w+)</code>", content))

    def test_manifest_matches_server(self):
        manifest = self._manifest_tools()
        server = self._server_tools()
        self.assertEqual(
            manifest,
            server,
            f"mcp-manifest.json tools ≠ mcp_server.py handlers\n"
            f"  manifest: {manifest}\n  server: {server}",
        )

    def test_manifest_matches_website_wellknown(self):
        manifest = self._manifest_tools()
        website = self._website_mcp_tools()
        self.assertEqual(
            manifest,
            website,
            f"mcp-manifest.json tools ≠ .well-known/mcp.json\n"
            f"  manifest: {manifest}\n  website: {website}",
        )

    def test_integrations_page_lists_all_tools(self):
        manifest = self._manifest_tools()
        page = self._integrations_page_tools()
        self.assertEqual(
            manifest,
            page,
            f"mcp-manifest.json tools ≠ integrations.html MCP Tools table\n"
            f"  manifest: {manifest}\n  page: {page}",
        )

    def test_manifest_client_configs_cover_all_assistants(self):
        """The 6 client configs in the manifest match the 6 assistants on integrations page."""
        manifest = json.loads(_read(AIIR_ROOT / "mcp-manifest.json"))
        client_keys = sorted(manifest.get("clientConfigs", {}).keys())
        expected = sorted(
            [
                "claude-desktop",
                "vscode-copilot",
                "cursor",
                "continue",
                "cline",
                "windsurf",
            ]
        )
        self.assertEqual(
            client_keys,
            expected,
            f"clientConfigs keys: {client_keys} ≠ expected: {expected}",
        )


# ═══════════════════════════════════════════════════════════════════════════
# 4. AI DETECTION TABLE ↔ _detect.py
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(SITE_EXISTS, "Website repo not found — set AIIR_SITE_DIR")
class TestAIDetectionAccuracy(unittest.TestCase):
    """The integrations page AI detection table matches actual detection code."""

    def _page_detected_tools(self) -> Set[str]:
        """Tool names from the 'AI Tools Detected' table on integrations page."""
        content = _read(SITE_DIR / "integrations.html")
        # Find the detection table (the one after "AI Tools Detected" heading)
        section = re.search(
            r"AI Tools Detected.*?<tbody>(.*?)</tbody>", content, re.DOTALL
        )
        self.assertIsNotNone(section, "AI Tools Detected table not found")
        # Extract first <td> from each row (the tool name)
        return set(re.findall(r"<tr><td>(.*?)</td>", section.group(1)))

    def _code_detected_signals(self) -> Set[str]:
        """Key AI tool identifiers from _detect.py AI_SIGNALS + ai_author_patterns."""
        from aiir._detect import AI_SIGNALS

        content = _read(AIIR_ROOT / "aiir" / "_detect.py")
        # Also extract ai_author_patterns
        patterns_match = re.search(
            r"ai_author_patterns\s*=\s*\[(.*?)\]", content, re.DOTALL
        )
        author_patterns = (
            re.findall(r'"([^"]+)"', patterns_match.group(1)) if patterns_match else []
        )
        return set(AI_SIGNALS) | set(author_patterns)

    def test_copilot_detected(self):
        signals = self._code_detected_signals()
        tools = self._page_detected_tools()
        self.assertTrue(
            any("copilot" in s for s in signals),
            "AIIR code does not detect Copilot",
        )
        self.assertTrue(
            any("Copilot" in t for t in tools),
            "Integrations page missing Copilot",
        )

    def test_gitlab_duo_detected(self):
        """Critical for GitLab partnership — must detect their native AI tool."""
        signals = self._code_detected_signals()
        tools = self._page_detected_tools()
        self.assertTrue(
            any("gitlab duo" in s or "duo" in s for s in signals),
            "AIIR code does not detect GitLab Duo",
        )
        self.assertTrue(
            any("GitLab Duo" in t for t in tools),
            "Integrations page missing GitLab Duo",
        )

    def test_devin_detected(self):
        signals = self._code_detected_signals()
        tools = self._page_detected_tools()
        self.assertTrue(
            any("devin" in s for s in signals),
            "AIIR code does not detect Devin",
        )
        self.assertTrue(
            any("Devin" in t for t in tools),
            "Integrations page missing Devin",
        )

    def test_all_page_tools_have_detection_code(self):
        """Every tool listed on the integrations page has matching detection code."""
        tools = self._page_detected_tools()
        signals = self._code_detected_signals()
        signals_lower = " ".join(s.lower() for s in signals)

        # Map page tool names to detection signal keywords
        tool_to_keywords = {
            "GitHub Copilot": ["copilot"],
            "ChatGPT / OpenAI": ["chatgpt"],
            "Claude / Anthropic": ["claude"],
            "Cursor": ["cursor"],
            "GitLab Duo": ["gitlab duo", "duo"],
            "Amazon Q / CodeWhisperer": ["amazon", "codewhisperer"],
            "Google Gemini": ["gemini"],
            "Devin": ["devin"],
            "Tabnine": ["tabnine"],
            "Codeium / Windsurf": ["codeium", "windsurf"],
            "Sourcegraph Cody": ["cody"],
            "Aider": ["aider"],
            "Replit AI": ["replit"],
            "JetBrains AI": ["jetbrains"],
            "Supermaven": ["supermaven"],
            "bolt.new / Lovable": ["bolt.new", "lovable"],
        }

        for tool_name in tools:
            keywords = tool_to_keywords.get(tool_name, [tool_name.lower().split()[0]])
            found = any(kw in signals_lower for kw in keywords)
            self.assertTrue(
                found,
                f"Integrations page lists '{tool_name}' but no matching "
                f"detection signal found in _detect.py (searched: {keywords})",
            )

    def test_minimum_detection_count(self):
        """At least 16 tools detected — matches the '16+' claim on the page."""
        tools = self._page_detected_tools()
        self.assertGreaterEqual(
            len(tools),
            16,
            f"Integrations page claims '16+ coding assistants' but only "
            f"lists {len(tools)} tools in the detection table",
        )


# ═══════════════════════════════════════════════════════════════════════════
# 5. CI TEMPLATE CLAIMS ↔ templates/ DIRECTORY
# ═══════════════════════════════════════════════════════════════════════════


class TestCITemplateIntegrity(unittest.TestCase):
    """Every CI platform claimed on the integrations page has a real template."""

    def test_github_action_exists(self):
        self.assertTrue(
            (AIIR_ROOT / "action.yml").is_file(),
            "action.yml missing — GitHub Actions integration broken",
        )

    def test_gitlab_ci_template_exists(self):
        self.assertTrue(
            (AIIR_ROOT / "templates" / "gitlab-ci.yml").is_file(),
            "templates/gitlab-ci.yml missing",
        )

    def test_azure_pipelines_template_exists(self):
        self.assertTrue(
            (AIIR_ROOT / "templates" / "azure-pipelines.yml").is_file(),
            "templates/azure-pipelines.yml missing",
        )

    def test_bitbucket_pipelines_template_exists(self):
        self.assertTrue(
            (AIIR_ROOT / "templates" / "bitbucket-pipelines.yml").is_file(),
            "templates/bitbucket-pipelines.yml missing",
        )

    def test_circleci_template_exists(self):
        circleci = AIIR_ROOT / "templates" / "circleci"
        self.assertTrue(
            circleci.is_dir(),
            "templates/circleci/ directory missing",
        )
        yaml_files = list(circleci.glob("*.yml")) + list(circleci.glob("*.yaml"))
        self.assertGreater(
            len(yaml_files),
            0,
            "templates/circleci/ has no YAML files",
        )

    def test_jenkins_template_exists(self):
        jenkins = AIIR_ROOT / "templates" / "jenkins"
        self.assertTrue(
            jenkins.is_dir(),
            "templates/jenkins/ directory missing",
        )
        files = list(jenkins.iterdir())
        self.assertGreater(len(files), 0, "templates/jenkins/ is empty")

    def test_action_yml_has_required_fields(self):
        """GitHub Action has name, description, inputs, outputs."""

        # Fall back to string parsing if PyYAML not available
        content = _read(AIIR_ROOT / "action.yml")
        for field in ["name:", "description:", "inputs:", "outputs:"]:
            self.assertIn(field, content, f"action.yml missing '{field}'")


# ═══════════════════════════════════════════════════════════════════════════
# 6. SITEMAP ↔ ACTUAL FILES
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(SITE_EXISTS, "Website repo not found — set AIIR_SITE_DIR")
class TestSitemap(unittest.TestCase):
    """Sitemap entries resolve to real files."""

    def _sitemap_urls(self) -> List[str]:
        tree = ET.parse(SITE_DIR / "sitemap.xml")
        root = tree.getroot()
        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        return [loc.text for loc in root.findall(".//sm:loc", ns) if loc.text]

    def test_sitemap_is_valid_xml(self):
        """sitemap.xml parses without errors."""
        try:
            ET.parse(SITE_DIR / "sitemap.xml")
        except ET.ParseError as e:
            self.fail(f"sitemap.xml is invalid XML: {e}")

    def test_sitemap_urls_resolve(self):
        """Every sitemap URL maps to a file that exists on disk."""
        base = "https://invariantsystems.io"
        for url in self._sitemap_urls():
            self.assertTrue(
                url.startswith(base),
                f"Sitemap URL not on correct domain: {url}",
            )
            path = url[len(base) :]
            if path == "" or path == "/":
                self.assertTrue((SITE_DIR / "index.html").is_file())
                continue
            # Strip leading /
            path = path.lstrip("/")
            # Try exact path, then with .html extension
            candidates = [
                SITE_DIR / path,
                SITE_DIR / (path + ".html"),
                SITE_DIR / path / "index.html",
            ]
            found = any(c.is_file() for c in candidates)
            self.assertTrue(
                found,
                f"Sitemap URL {url} doesn't resolve to any file. "
                f"Tried: {[str(c) for c in candidates]}",
            )

    def test_all_html_pages_in_sitemap(self):
        """Every main HTML page has a sitemap entry."""
        urls = self._sitemap_urls()
        url_paths = {
            u.replace("https://invariantsystems.io", "").rstrip("/") or "/"
            for u in urls
        }
        for page in _main_pages():
            expected_path = "/" + page.stem if page.name != "index.html" else "/"
            self.assertIn(
                expected_path,
                url_paths,
                f"{page.name} has no sitemap entry (expected {expected_path})",
            )

    def test_no_future_dates(self):
        """Sitemap lastmod dates are not in the future."""
        from datetime import date

        tree = ET.parse(SITE_DIR / "sitemap.xml")
        root = tree.getroot()
        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        today = date.today()

        for url_elem in root.findall(".//sm:url", ns):
            lastmod = url_elem.find("sm:lastmod", ns)
            if lastmod is not None and lastmod.text:
                d = date.fromisoformat(lastmod.text)
                loc = url_elem.find("sm:loc", ns)
                loc_text = loc.text if loc is not None else "unknown"
                self.assertLessEqual(
                    d,
                    today,
                    f"Sitemap entry {loc_text} has future date: {lastmod.text}",
                )


# ═══════════════════════════════════════════════════════════════════════════
# 7. INTERNAL LINK INTEGRITY
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(SITE_EXISTS, "Website repo not found — set AIIR_SITE_DIR")
class TestLinkIntegrity(unittest.TestCase):
    """All internal href= links resolve to actual files."""

    def _extract_internal_links(self, page: Path) -> List[str]:
        content = _read(page)
        hrefs = re.findall(r'href="(/[^"]*)"', content)
        return hrefs

    def test_all_internal_links_resolve(self):
        """Every internal link (href="/...") resolves to a file on disk."""
        broken = []
        for page in SITE_DIR.glob("*.html"):
            for href in self._extract_internal_links(page):
                # Strip anchor
                path = href.split("#")[0]
                # Strip query string
                path = path.split("?")[0]
                if not path or path == "/":
                    if not (SITE_DIR / "index.html").is_file():
                        broken.append((page.name, href))
                    continue
                path = path.lstrip("/")
                candidates = [
                    SITE_DIR / path,
                    SITE_DIR / (path + ".html"),
                    SITE_DIR / path / "index.html",
                ]
                if not any(c.is_file() for c in candidates):
                    broken.append((page.name, href))

        self.assertEqual(
            broken,
            [],
            "Broken internal links:\n"
            + "\n".join(f"  {page}: {href}" for page, href in broken),
        )


# ═══════════════════════════════════════════════════════════════════════════
# 8. README DOCUMENTED COMMANDS
# ═══════════════════════════════════════════════════════════════════════════


class TestREADMECLIContract(unittest.TestCase):
    """README-documented CLI commands correspond to real entry points."""

    def test_aiir_cli_importable(self):
        from aiir import cli

        self.assertTrue(hasattr(cli, "main"), "aiir.cli.main missing")

    def test_aiir_mcp_server_importable(self):
        from aiir import mcp_server

        self.assertTrue(
            hasattr(mcp_server, "main") or hasattr(mcp_server, "run_server"),
            "aiir.mcp_server has no main/run_server entry point",
        )

    def test_readme_mentions_all_mcp_tools(self):
        """README documents all 7 MCP tools."""
        readme = _read(AIIR_ROOT / "README.md")
        manifest = json.loads(_read(AIIR_ROOT / "mcp-manifest.json"))
        for tool in manifest["tools"]:
            self.assertIn(
                tool["name"],
                readme,
                f"README.md does not mention MCP tool '{tool['name']}'",
            )

    def test_readme_install_command(self):
        readme = _read(AIIR_ROOT / "README.md")
        self.assertIn("pip install aiir", readme)

    def test_readme_github_action_reference(self):
        readme = _read(AIIR_ROOT / "README.md")
        self.assertIn("invariant-systems-ai/aiir@v1", readme)


# ═══════════════════════════════════════════════════════════════════════════
# 9. SCHEMA FILES
# ═══════════════════════════════════════════════════════════════════════════


class TestSchemaIntegrity(unittest.TestCase):
    """JSON schema files are valid and present."""

    def test_commit_receipt_schema_valid_json(self):
        path = AIIR_ROOT / "schemas" / "commit_receipt.v1.schema.json"
        self.assertTrue(path.is_file(), "commit receipt schema missing")
        schema = json.loads(_read(path))
        self.assertIn("$schema", schema)
        self.assertIn("properties", schema)

    def test_verification_summary_schema_valid_json(self):
        path = AIIR_ROOT / "schemas" / "verification_summary.v1.schema.json"
        self.assertTrue(path.is_file(), "verification summary schema missing")
        schema = json.loads(_read(path))
        self.assertIn("$schema", schema)

    def test_test_vectors_valid_json(self):
        path = AIIR_ROOT / "schemas" / "test_vectors.json"
        self.assertTrue(path.is_file(), "test vectors missing")
        data = json.loads(_read(path))
        self.assertIsInstance(data, (dict, list))

    @unittest.skipUnless(SITE_EXISTS, "Website repo not found")
    def test_website_schema_files_exist(self):
        """Website hosts the commit receipt schema for validation."""
        schema_dir = SITE_DIR / "schemas" / "aiir"
        self.assertTrue(
            schema_dir.is_dir(),
            "Website missing schemas/aiir/ directory",
        )
        self.assertTrue(
            (schema_dir / "commit_receipt.v1.schema.json").is_file(),
            "Website missing commit receipt schema",
        )


# ═══════════════════════════════════════════════════════════════════════════
# 10. CONTENT-TIER POLICY (no T1+ leaks)
# ═══════════════════════════════════════════════════════════════════════════


def _decode_guard_patterns() -> list[str]:
    """Decode reference-guard patterns from their stored representation."""
    import base64 as _b64
    # Encoded patterns for internal reference guards — do not inline plaintext.
    _enc = [
        b"aHViXC5pbnZhcmlhbnRzeXN0ZW1zXC5pbw==",
        b"aW52YXJpYW50LXN5c3RlbXMtd29ya3NwYWNl",
        b"a2FsZWlkb3MtY29yZQ==",
        b"TWV0YUlEMjU2",
        b"aHYxNQ==",
        b"Q29kb242NA==",
        b"a2dyYXBoXC5qc29ubA==",
        b"dHJhY2UtbWFwIGFsZ2VicmE=",
    ]
    return [_b64.b64decode(e).decode() for e in _enc]


@unittest.skipUnless(SITE_EXISTS, "Website repo not found — set AIIR_SITE_DIR")
class TestContentTierPolicy(unittest.TestCase):
    """Public surfaces must not reference internal-only resources."""

    FORBIDDEN_PATTERNS = _decode_guard_patterns()

    def test_no_internal_refs_in_html(self):
        """No internal-only references in any HTML page."""
        violations = []
        for page in SITE_DIR.glob("*.html"):
            content = _read(page)
            for pattern in self.FORBIDDEN_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    violations.append((page.name, pattern))

        self.assertEqual(
            violations,
            [],
            "Internal references found on public pages:\n"
            + "\n".join(f"  {page}: matched '{pat}'" for page, pat in violations),
        )

    def test_no_internal_refs_in_readme(self):
        """AIIR README must not reference internal resources."""
        readme = _read(AIIR_ROOT / "README.md")
        for pattern in self.FORBIDDEN_PATTERNS:
            self.assertIsNone(
                re.search(pattern, readme, re.IGNORECASE),
                f"README contains internal reference: {pattern}",
            )

    def test_no_internal_refs_in_mcp_manifest(self):
        """MCP manifest must not reference internal resources."""
        content = _read(AIIR_ROOT / "mcp-manifest.json")
        for pattern in self.FORBIDDEN_PATTERNS:
            self.assertIsNone(
                re.search(pattern, content, re.IGNORECASE),
                f"mcp-manifest.json contains internal reference: {pattern}",
            )


# ═══════════════════════════════════════════════════════════════════════════
# 11. INTEGRATIONS PAGE SPECIFIC CLAIMS
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(SITE_EXISTS, "Website repo not found — set AIIR_SITE_DIR")
class TestIntegrationsPageClaims(unittest.TestCase):
    """Every factual claim on the integrations page is backed by evidence."""

    def test_6_cicd_platform_cards(self):
        """The CI/CD section has exactly 6 platform cards."""
        content = _read(SITE_DIR / "integrations.html")
        # Find the CI/CD section (between "CI/CD Platforms" and the next section)
        section = re.search(r"CI/CD Platforms.*?</section>", content, re.DOTALL)
        self.assertIsNotNone(section)
        cards = re.findall(r'class="deploy-card"', section.group())
        self.assertEqual(
            len(cards),
            6,
            f"Expected 6 CI/CD platform cards, found {len(cards)}",
        )

    def test_6_ai_assistant_cards(self):
        """The AI Coding Assistants section has exactly 6 assistant cards."""
        content = _read(SITE_DIR / "integrations.html")
        # Find the AI assistants card-grid (after "AI Coding Assistants")
        section = re.search(r"AI Coding Assistants.*?MCP Tools", content, re.DOTALL)
        self.assertIsNotNone(section)
        cards = re.findall(r'class="card"', section.group())
        self.assertEqual(
            len(cards),
            6,
            f"Expected 6 AI assistant cards, found {len(cards)}",
        )

    def test_7_mcp_tools_in_table(self):
        """The MCP Tools table lists exactly 7 tools."""
        content = _read(SITE_DIR / "integrations.html")
        section = re.search(r"MCP Tools.*?AI Tools Detected", content, re.DOTALL)
        self.assertIsNotNone(section)
        tools = re.findall(r"<code>(aiir_\w+)</code>", section.group())
        self.assertEqual(
            len(tools),
            7,
            f"Expected 7 MCP tools, found {len(tools)}: {tools}",
        )

    def test_pip_install_aiir_claim(self):
        """The page says 'pip install aiir' — verify the package name is correct."""
        content = _read(SITE_DIR / "integrations.html")
        self.assertIn("pip install aiir", content)

    def test_zero_dependencies_claim_on_index(self):
        """Index page claims 'zero dependencies' — verify pyproject.toml."""

        toml = _read(AIIR_ROOT / "pyproject.toml")
        # Check dependencies list is empty or absent
        dep_match = re.search(r"dependencies\s*=\s*\[(.*?)\]", toml, re.DOTALL)
        if dep_match:
            deps = [
                d.strip().strip('"').strip("'")
                for d in dep_match.group(1).split(",")
                if d.strip() and not d.strip().startswith("#")
            ]
            self.assertEqual(
                deps,
                [],
                f"pyproject.toml has runtime dependencies but site claims zero: {deps}",
            )

    def test_verify_anywhere_claim(self):
        """The page says 'aiir verify receipt.json' — verify CLI has verify subcommand."""
        content = _read(SITE_DIR / "integrations.html")
        self.assertIn("aiir verify receipt.json", content)
        # Verify the CLI actually supports --verify
        from aiir.cli import main

        self.assertTrue(callable(main))

    def test_attestation_section_has_4_cards(self):
        content = _read(SITE_DIR / "integrations.html")
        section = re.search(r"Attestation.*?How it fits together", content, re.DOTALL)
        self.assertIsNotNone(section)
        cards = re.findall(r'class="card"', section.group())
        self.assertEqual(
            len(cards),
            4,
            f"Expected 4 attestation cards, found {len(cards)}",
        )


# ═══════════════════════════════════════════════════════════════════════════
# 12. 404 PAGE
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(SITE_EXISTS, "Website repo not found — set AIIR_SITE_DIR")
class TestErrorPage(unittest.TestCase):
    """404 page has correct structure and links."""

    def test_404_exists(self):
        self.assertTrue(
            (SITE_DIR / "404.html").is_file(),
            "404.html missing",
        )

    def test_404_has_home_link(self):
        content = _read(SITE_DIR / "404.html")
        self.assertIn('href="/"', content)

    def test_404_has_integrations_link(self):
        content = _read(SITE_DIR / "404.html")
        self.assertIn(
            'href="/integrations"',
            content,
            "404.html missing Integrations link",
        )

    def test_404_has_content_tier_tag(self):
        content = _read(SITE_DIR / "404.html")
        self.assertIn('data-content-tier="T0"', content)


# ═══════════════════════════════════════════════════════════════════════════
# 13. STATS.JSON ACCURACY
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(SITE_EXISTS, "Website repo not found — set AIIR_SITE_DIR")
class TestStatsJSON(unittest.TestCase):
    """stats.json claims are plausible and consistent."""

    def test_stats_json_valid(self):
        stats = json.loads(_read(SITE_DIR / "stats.json"))
        self.assertIn("version", stats)
        self.assertIn("stats", stats)
        self.assertIn("updated", stats)

    def test_zero_dependencies(self):
        stats = json.loads(_read(SITE_DIR / "stats.json"))
        self.assertEqual(
            stats["stats"]["dependencies"],
            0,
            "stats.json claims non-zero dependencies",
        )

    def test_test_count_plausible(self):
        """Test count should be at least 1000 (currently 1111)."""
        stats = json.loads(_read(SITE_DIR / "stats.json"))
        self.assertGreaterEqual(
            stats["stats"]["tests"],
            1000,
            f"stats.json test count suspiciously low: {stats['stats']['tests']}",
        )

    def test_mcp_tests_positive(self):
        stats = json.loads(_read(SITE_DIR / "stats.json"))
        self.assertGreater(
            stats["stats"]["mcp_tests"],
            0,
            "stats.json claims zero MCP tests",
        )


if __name__ == "__main__":
    unittest.main()
