#!/usr/bin/env python3
"""
fetch_public_site_snapshot.py — Fetch a filesystem snapshot of public site assets for CI tests.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import re
import time
import sys
import urllib.parse
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections import deque
from pathlib import Path


BASE_URL = "https://invariantsystems.io"
HTML_HREF_RE = re.compile(r'href="([^"]+)"', re.IGNORECASE)
MAX_FETCHED_PATHS = 128
ALLOWED_FETCH_SUFFIXES = {
    "",
    ".css",
    ".html",
    ".ico",
    ".js",
    ".json",
    ".png",
    ".svg",
    ".webmanifest",
    ".xml",
}
INITIAL_PATHS = {
    "/",
    "/404.html",
    "/.well-known/mcp.json",
    "/schemas/aiir/commit_receipt.v1.schema.json",
    "/stats.json",
}


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "aiir-public-surface-ci/1.0"},
    )
    attempts = 3
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read()
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            if attempt == attempts:
                raise RuntimeError(f"Failed to fetch {url}: {exc}") from exc
            time.sleep(attempt)
    raise RuntimeError(f"Failed to fetch {url}: exhausted retries")


def _site_path_to_file(path: str) -> Path:
    if path == "/":
        return Path("index.html")

    trimmed = path.lstrip("/")
    parts = Path(trimmed).parts
    if any(part == ".." for part in parts):
        raise RuntimeError(f"Path traversal detected for {path!r}")

    if path.endswith("/"):
        return Path(trimmed) / "index.html"

    suffix = Path(trimmed).suffix
    if suffix:
        return Path(trimmed)

    if "/" in trimmed:
        return Path(trimmed) / "index.html"

    return Path(f"{trimmed}.html")


def _extract_sitemap_paths(xml_text: str) -> set[str]:
    namespace = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    root = ET.fromstring(xml_text)
    paths: set[str] = set()
    for loc in root.findall(".//sm:loc", namespace):
        if not loc.text:
            continue
        parsed = urllib.parse.urlparse(loc.text.strip())
        if parsed.netloc != urllib.parse.urlparse(BASE_URL).netloc:
            continue
        if parsed.scheme not in {"http", "https"}:
            continue
        paths.add(parsed.path or "/")
    return paths


def _extract_internal_paths(html_text: str) -> set[str]:
    paths: set[str] = set()
    for href in HTML_HREF_RE.findall(html_text):
        if not href or href.startswith("#"):
            continue
        if href.startswith(("mailto:", "tel:")):
            continue

        parsed = urllib.parse.urlparse(href)
        if parsed.scheme or parsed.netloc:
            if (
                parsed.netloc
                and parsed.netloc != urllib.parse.urlparse(BASE_URL).netloc
            ):
                continue
        path = parsed.path or "/"
        suffix = Path(path).suffix
        if path.startswith("/") and (
            suffix in ALLOWED_FETCH_SUFFIXES
            or path.startswith("/.well-known/")
            or path.startswith("/schemas/")
        ):
            paths.add(path)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch a filesystem snapshot of public invariantsystems.io assets for CI tests.",
    )
    parser.add_argument(
        "output_dir", help="Directory to write the fetched site snapshot into."
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    sitemap_bytes = _fetch(f"{BASE_URL}/sitemap.xml")
    sitemap_text = sitemap_bytes.decode("utf-8")
    (output_dir / "sitemap.xml").write_bytes(sitemap_bytes)

    queued = deque(sorted(INITIAL_PATHS | _extract_sitemap_paths(sitemap_text)))
    seen: set[str] = set()

    while queued:
        if len(seen) >= MAX_FETCHED_PATHS:
            raise RuntimeError(
                f"Refusing to fetch more than {MAX_FETCHED_PATHS} site paths"
            )
        path = queued.popleft()
        if path in seen:
            continue
        seen.add(path)

        url = urllib.parse.urljoin(BASE_URL, path)
        body = _fetch(url)
        destination = output_dir / _site_path_to_file(path)
        destination_resolved = destination.resolve()
        if not destination_resolved.is_relative_to(output_dir):
            raise RuntimeError(
                f"Path traversal detected for {path!r}: {destination_resolved}"
            )
        destination_resolved.parent.mkdir(parents=True, exist_ok=True)
        destination_resolved.write_bytes(body)

        if destination_resolved.suffix == ".html":
            html_text = body.decode("utf-8")
            for linked_path in sorted(_extract_internal_paths(html_text)):
                if linked_path not in seen:
                    queued.append(linked_path)

    print(f"Fetched {len(seen)} site paths into {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
