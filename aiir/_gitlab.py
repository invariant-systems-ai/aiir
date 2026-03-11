"""
AIIR internal — GitLab CI/CD integration helpers.

Parallel to ``_github.py`` — provides native GitLab integration:
  - MR comment posting via CI_API_V4_URL + CI_JOB_TOKEN
  - GitLab-flavored Markdown summary formatting
  - CI/CD dotenv output for downstream variable passing
  - gl-sast-report.json for Security Dashboard integration
  - MR Approval Rules enforcement via API
  - Webhook payload parsing for server-side receipt generation
  - GraphQL query helpers for receipt data retrieval

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hashlib
import html
import json
import logging
import os
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from aiir._core import (
    CLI_VERSION,
    _sanitize_md,
    _strip_terminal_escapes,
)

logger = logging.getLogger("aiir.gitlab")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# GitLab SAST report schema version
# https://gitlab.com/gitlab-org/security-products/security-report-schemas
_GL_SAST_SCHEMA = "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v15.1.1/dist/sast-report-format.json"

# Maximum MR comment body size (GitLab limit is ~1 MB for notes)
_MAX_COMMENT_SIZE = 512 * 1024  # 512 KB (conservative)

# HTTP timeout for GitLab API calls
_API_TIMEOUT = 30


# ---------------------------------------------------------------------------
# CI/CD Output: dotenv artifact for downstream variable passing
# ---------------------------------------------------------------------------


def set_gitlab_ci_output(
    key: str, value: str, dotenv_path: Optional[str] = None
) -> None:
    """Write a key=value pair to a dotenv artifact file for downstream jobs.

    GitLab CI passes variables between jobs via dotenv artifacts:
    https://docs.gitlab.com/ee/ci/yaml/artifacts_reports.html#artifactsreportsdotenv

    The dotenv file must be declared as an artifact in the job:
        artifacts:
          reports:
            dotenv: aiir.env

    Args:
        key: Variable name (must be alphanumeric + underscore).
        value: Variable value.
        dotenv_path: Path to the dotenv file (default: ``aiir.env``).
    """
    # Validate key — GitLab CI variables must be alphanumeric + underscore
    if not key or not key.replace("_", "").isalnum():
        raise ValueError(
            f"Invalid GitLab CI output key (must be alphanumeric + underscore): {key!r}"
        )
    # Prevent newline injection in values
    safe_value = value.replace("\n", "\\n").replace("\r", "")
    path = dotenv_path or "aiir.env"
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{key}={safe_value}\n")


# ---------------------------------------------------------------------------
# MR Comment posting
# ---------------------------------------------------------------------------


def _gitlab_api_request(
    method: str,
    endpoint: str,
    body: Optional[Dict[str, Any]] = None,
    api_url: Optional[str] = None,
    token: Optional[str] = None,
) -> Dict[str, Any]:
    """Make an authenticated request to the GitLab API.

    Uses CI_JOB_TOKEN (zero-config in pipelines) or GITLAB_TOKEN for
    broader permissions.  Falls back gracefully when neither is available.

    Args:
        method: HTTP method (GET, POST, PUT).
        endpoint: API endpoint path (e.g., ``/projects/123/merge_requests/1/notes``).
        body: JSON request body (for POST/PUT).
        api_url: Override for CI_API_V4_URL.
        token: Override for authentication token.

    Returns:
        Parsed JSON response as a dict.

    Raises:
        RuntimeError: If the API call fails.
    """
    base_url = api_url or os.environ.get("CI_API_V4_URL", "")
    if not base_url:
        raise RuntimeError(
            "GitLab API URL not available. Set CI_API_V4_URL or run in GitLab CI."
        )

    auth_token = (
        token or os.environ.get("GITLAB_TOKEN") or os.environ.get("CI_JOB_TOKEN")
    )
    if not auth_token:
        raise RuntimeError(
            "No GitLab authentication token. Set GITLAB_TOKEN or run in GitLab CI "
            "(CI_JOB_TOKEN is automatic)."
        )

    # Validate URL scheme to prevent SSRF (e.g. file://, gopher://).
    from urllib.parse import urlparse as _urlparse

    _parsed = _urlparse(base_url)
    if _parsed.scheme not in ("https", "http"):
        raise RuntimeError(
            f"Refusing API request to non-HTTP(S) URL scheme: {_parsed.scheme!r}"
        )

    url = f"{base_url.rstrip('/')}{endpoint}"
    headers: Dict[str, str] = {"Content-Type": "application/json"}

    # CI_JOB_TOKEN uses JOB-TOKEN header; personal/project tokens use PRIVATE-TOKEN
    if os.environ.get("CI_JOB_TOKEN") and auth_token == os.environ.get("CI_JOB_TOKEN"):
        headers["JOB-TOKEN"] = auth_token
    else:
        headers["PRIVATE-TOKEN"] = auth_token

    data = json.dumps(body).encode("utf-8") if body else None
    req = Request(url, data=data, headers=headers, method=method)

    try:
        with urlopen(req, timeout=_API_TIMEOUT) as resp:  # nosec B310  # nosemgrep
            result: dict[str, Any] = json.loads(resp.read().decode("utf-8"))
            return result
    except HTTPError as e:
        error_body = ""
        try:
            error_body = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        raise RuntimeError(
            f"GitLab API error {e.code} on {method} {endpoint}: {error_body}"
        ) from e
    except URLError as e:
        raise RuntimeError(f"GitLab API connection error: {e.reason}") from e


def post_mr_comment(
    comment: str,
    project_id: Optional[str] = None,
    mr_iid: Optional[str] = None,
    api_url: Optional[str] = None,
    token: Optional[str] = None,
) -> Dict[str, Any]:
    """Post a comment (note) on a GitLab merge request.

    In GitLab CI, project ID and MR IID are auto-detected from
    CI_PROJECT_ID and CI_MERGE_REQUEST_IID environment variables.

    Args:
        comment: Markdown comment body.
        project_id: GitLab project ID (auto-detected in CI).
        mr_iid: Merge request internal ID (auto-detected in CI).
        api_url: Override for CI_API_V4_URL.
        token: Override for authentication token.

    Returns:
        API response dict with the created note.

    Raises:
        RuntimeError: If not in MR context or API call fails.
    """
    pid = project_id or os.environ.get("CI_PROJECT_ID")
    iid = mr_iid or os.environ.get("CI_MERGE_REQUEST_IID")

    if not pid or not iid:
        raise RuntimeError(
            "Not in a merge request context. CI_PROJECT_ID and "
            "CI_MERGE_REQUEST_IID are required."
        )

    # Truncate comment to stay within GitLab limits
    if len(comment.encode("utf-8", errors="replace")) > _MAX_COMMENT_SIZE:
        suffix = "\n\n*(truncated — exceeded 512 KB limit)*"
        budget = _MAX_COMMENT_SIZE - len(suffix.encode("utf-8"))
        comment = (
            comment.encode("utf-8")[:budget].decode("utf-8", errors="ignore") + suffix
        )

    # URL-encode pid and iid to prevent path traversal on the API.
    from urllib.parse import quote as _quote

    return _gitlab_api_request(
        "POST",
        f"/projects/{_quote(str(pid), safe='')}/merge_requests/{_quote(str(iid), safe='')}/notes",
        body={"body": comment},
        api_url=api_url,
        token=token,
    )


# ---------------------------------------------------------------------------
# GitLab-flavored Markdown summary
# ---------------------------------------------------------------------------


def format_gitlab_summary(receipts: List[Dict[str, Any]]) -> str:
    """Format receipts as a GitLab-flavored Markdown summary.

    Uses collapsible ``<details>`` blocks and GitLab-flavored Markdown
    (GFM) for native rendering in MR comments and descriptions.

    Args:
        receipts: List of AIIR receipt dicts.

    Returns:
        GitLab-flavored Markdown string.
    """
    ai_count = sum(
        1
        for r in receipts
        if isinstance(r.get("ai_attestation"), dict)
        and r["ai_attestation"].get("is_ai_authored")
    )
    total = len(receipts)
    ai_pct = (ai_count / total * 100) if total > 0 else 0

    lines = [
        "## 🔐 AIIR Receipt Summary",
        "",
        f"**{total}** commit{'s' if total != 1 else ''} receipted"
        + (f" · **{ai_count}** AI-authored ({ai_pct:.0f}%)" if ai_count else ""),
        "",
    ]

    # Summary table
    lines.extend(
        [
            "| Commit | Subject | Class | Receipt ID |",
            "|--------|---------|-------|-----------|",
        ]
    )

    for r in receipts:
        commit = r.get("commit", {})
        ai = r.get("ai_attestation", {})
        if not isinstance(commit, dict):
            commit = {}
        if not isinstance(ai, dict):
            ai = {}
        sha_short = _sanitize_md(commit.get("sha", "")[:8])
        subject = _sanitize_md(commit.get("subject", "")[:50])
        authorship = _sanitize_md(ai.get("authorship_class", "unknown"))
        rid = _sanitize_md(r.get("receipt_id", "")[:16]) + "…"
        icon = {"human": "👤", "ai_assisted": "🤖", "bot": "⚙️", "ai+bot": "🤖⚙️"}.get(
            ai.get("authorship_class", ""), ""
        )
        lines.append(f"| `{sha_short}` | {subject} | {icon} {authorship} | `{rid}` |")

    # Detailed view in collapsible block
    lines.extend(
        [
            "",
            "<details>",
            "<summary>📋 Detailed receipt information</summary>",
            "",
        ]
    )

    for r in receipts:
        commit = r.get("commit", {})
        ai = r.get("ai_attestation", {})
        if not isinstance(commit, dict):
            commit = {}
        if not isinstance(ai, dict):
            ai = {}
        sha = commit.get("sha", "unknown")[:12]
        lines.extend(
            [
                f"**{sha}** — {_sanitize_md(commit.get('subject', '')[:80])}",
                f"- Authorship: `{ai.get('authorship_class', 'unknown')}`",
                f"- AI signals: {ai.get('signal_count', 0)}",
                f"- Content hash: `{r.get('content_hash', '')[:32]}…`",
                f"- Receipt ID: `{r.get('receipt_id', '')}`",
                "",
            ]
        )

    lines.extend(
        [
            "</details>",
            "",
            f"*Generated by [AIIR](https://github.com/invariant-systems-ai/aiir) v{CLI_VERSION}*",
        ]
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Security Dashboard: gl-sast-report.json
# ---------------------------------------------------------------------------


def format_gl_sast_report(receipts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Format receipts as a GitLab SAST report for Security Dashboard.

    GitLab's Security Dashboard ingests ``gl-sast-report.json`` files
    (https://docs.gitlab.com/ee/development/integrations/secure.html).
    AIIR reports AI-authored commits without explicit receipts as
    informational findings, enabling native Security Dashboard visibility.

    Args:
        receipts: List of AIIR receipt dicts.

    Returns:
        Dict conforming to GitLab SAST report schema.
    """
    vulnerabilities = []
    for r in receipts:
        ai = r.get("ai_attestation", {})
        commit = r.get("commit", {})
        if not isinstance(ai, dict):
            ai = {}
        if not isinstance(commit, dict):
            commit = {}

        if not ai.get("is_ai_authored"):
            continue

        sha = commit.get("sha", "unknown")
        subject = _strip_terminal_escapes(str(commit.get("subject", "")))[:200]
        authorship_class = ai.get("authorship_class", "unknown")
        signals = ai.get("signals_detected", [])
        if not isinstance(signals, list):
            signals = []
        signal_str = ", ".join(str(s) for s in signals[:5])

        # Deterministic ID from commit SHA + receipt hash
        vuln_id = hashlib.sha256(
            f"aiir:{sha}:{r.get('content_hash', '')}".encode()
        ).hexdigest()

        vulnerabilities.append(
            {
                "id": vuln_id,
                "category": "sast",
                "name": f"AI-authored commit: {sha[:8]}",
                "message": (
                    f"Commit {sha[:12]} ({subject}) is classified as "
                    f"'{authorship_class}' with {len(signals)} AI signal(s) "
                    f"detected: {signal_str}"
                ),
                "description": (
                    f"AIIR detected AI authorship signals in commit {sha}. "
                    f"Authorship class: {authorship_class}. "
                    f"This is an informational finding for audit trail purposes. "
                    f"Receipt ID: {r.get('receipt_id', 'unknown')}."
                ),
                "severity": "Info",
                "confidence": "High" if len(signals) > 1 else "Medium",
                "scanner": {
                    "id": "aiir",
                    "name": "AIIR — AI Integrity Receipts",
                    "version": CLI_VERSION,
                    "vendor": {
                        "name": "Invariant Systems, Inc.",
                    },
                    "url": "https://github.com/invariant-systems-ai/aiir",
                },
                "identifiers": [
                    {
                        "type": "aiir_receipt",
                        "name": f"AIIR Receipt {r.get('receipt_id', '')[:24]}",
                        "value": r.get("receipt_id", ""),
                        "url": "https://github.com/invariant-systems-ai/aiir",
                    }
                ],
                "location": {
                    "file": commit.get("files", ["(redacted)"])[0]
                    if isinstance(commit.get("files"), list) and commit.get("files")
                    else "(see receipt)",
                    "start_line": 1,
                },
            }
        )

    return {
        "version": "15.1.1",
        "schema": _GL_SAST_SCHEMA,
        "scan": {
            "scanner": {
                "id": "aiir",
                "name": "AIIR — AI Integrity Receipts",
                "version": CLI_VERSION,
                "vendor": {
                    "name": "Invariant Systems, Inc.",
                },
                "url": "https://github.com/invariant-systems-ai/aiir",
            },
            "analyzer": {
                "id": "aiir",
                "name": "AIIR AI Authorship Analyzer",
                "version": CLI_VERSION,
                "vendor": {
                    "name": "Invariant Systems, Inc.",
                },
                "url": "https://github.com/invariant-systems-ai/aiir",
            },
            "type": "sast",
            "start_time": _safe_iso_now(),
            "end_time": _safe_iso_now(),
            "status": "success",
        },
        "vulnerabilities": vulnerabilities,
    }


def _safe_iso_now() -> str:
    """Return current UTC time in ISO 8601 format (no external deps)."""
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


# ---------------------------------------------------------------------------
# MR Approval Rules enforcement
# ---------------------------------------------------------------------------


def enforce_approval_rules(
    ai_percent: float,
    threshold: float = 50.0,
    required_approvals: int = 2,
    project_id: Optional[str] = None,
    mr_iid: Optional[str] = None,
    api_url: Optional[str] = None,
    token: Optional[str] = None,
) -> Dict[str, Any]:
    """Enforce additional MR approvals when AI authorship exceeds threshold.

    Uses the GitLab Merge Request Approval Rules API to dynamically
    require additional reviewers when AI-authored code percentage is high.

    https://docs.gitlab.com/ee/api/merge_request_approvals.html

    Args:
        ai_percent: Percentage of AI-authored commits in the MR.
        threshold: AI percentage threshold that triggers extra approvals.
        required_approvals: Number of approvals to require.
        project_id: GitLab project ID (auto-detected in CI).
        mr_iid: Merge request IID (auto-detected in CI).
        api_url: Override for CI_API_V4_URL.
        token: Override for auth token (requires API scope, not CI_JOB_TOKEN).

    Returns:
        Dict with action taken and API response.
    """
    if ai_percent < threshold:
        return {
            "action": "none",
            "ai_percent": ai_percent,
            "threshold": threshold,
            "message": f"AI% ({ai_percent:.1f}%) below threshold ({threshold:.1f}%) — no extra approvals needed",
        }

    pid = project_id or os.environ.get("CI_PROJECT_ID")
    iid = mr_iid or os.environ.get("CI_MERGE_REQUEST_IID")

    if not pid or not iid:
        return {
            "action": "skipped",
            "reason": "Not in MR context (CI_PROJECT_ID/CI_MERGE_REQUEST_IID missing)",
            "ai_percent": ai_percent,
        }

    try:
        from urllib.parse import quote as _quote

        result = _gitlab_api_request(
            "POST",
            f"/projects/{_quote(str(pid), safe='')}/merge_requests/{_quote(str(iid), safe='')}/approval_rules",
            body={
                "name": f"AIIR: AI-authored code review ({ai_percent:.0f}% AI)",
                "approvals_required": required_approvals,
            },
            api_url=api_url,
            token=token,
        )
        return {
            "action": "created",
            "ai_percent": ai_percent,
            "threshold": threshold,
            "required_approvals": required_approvals,
            "rule_id": result.get("id"),
            "message": (
                f"Created approval rule: {required_approvals} approvals required "
                f"(AI% = {ai_percent:.1f}%, threshold = {threshold:.1f}%)"
            ),
        }
    except RuntimeError as e:
        return {
            "action": "failed",
            "error": str(e),
            "ai_percent": ai_percent,
        }


# ---------------------------------------------------------------------------
# Webhook handler: server-side receipt generation
# ---------------------------------------------------------------------------


def parse_webhook_event(
    payload: Dict[str, Any],
) -> Optional[Dict[str, str]]:
    """Parse a GitLab webhook payload and extract commit/MR information.

    Supports ``push`` and ``merge_request`` event types.
    Returns a dict with normalized fields for receipt generation,
    or None if the event is not relevant.

    https://docs.gitlab.com/ee/user/project/integrations/webhook_events.html

    Args:
        payload: Parsed JSON webhook payload.

    Returns:
        Dict with ``event_type``, ``project_id``, ``ref``, ``before``,
        ``after``, ``mr_iid`` (if MR event), or None if not actionable.
    """
    if not isinstance(payload, dict):
        return None

    event_type = payload.get("object_kind") or payload.get("event_type")

    if event_type == "push":
        project = payload.get("project", {})
        if not isinstance(project, dict):
            project = {}
        return {
            "event_type": "push",
            "project_id": str(project.get("id", "")),
            "project_path": _strip_terminal_escapes(
                str(project.get("path_with_namespace", ""))
            ),
            "ref": _strip_terminal_escapes(str(payload.get("ref", ""))),
            "before": _strip_terminal_escapes(str(payload.get("before", ""))),
            "after": _strip_terminal_escapes(str(payload.get("after", ""))),
            "commit_count": str(payload.get("total_commits_count", 0)),
        }

    if event_type == "merge_request":
        attrs = payload.get("object_attributes", {})
        if not isinstance(attrs, dict):
            attrs = {}
        project = payload.get("project", {})
        if not isinstance(project, dict):
            project = {}
        return {
            "event_type": "merge_request",
            "project_id": str(project.get("id", "")),
            "project_path": _strip_terminal_escapes(
                str(project.get("path_with_namespace", ""))
            ),
            "mr_iid": str(attrs.get("iid", "")),
            "mr_action": _strip_terminal_escapes(str(attrs.get("action", ""))),
            "source_branch": _strip_terminal_escapes(
                str(attrs.get("source_branch", ""))
            ),
            "target_branch": _strip_terminal_escapes(
                str(attrs.get("target_branch", ""))
            ),
            "before": _strip_terminal_escapes(str(attrs.get("oldrev", ""))),
            "after": _strip_terminal_escapes(
                str(
                    attrs.get("last_commit", {}).get("id", "")
                    if isinstance(attrs.get("last_commit"), dict)
                    else ""
                )
            ),
        }

    # Unrecognized event type
    return None


def validate_webhook_token(
    request_token: str,
    expected_token: Optional[str] = None,
) -> bool:
    """Validate the GitLab webhook secret token.

    GitLab sends the secret token in the ``X-Gitlab-Token`` header.
    Uses constant-time comparison to prevent timing attacks.

    Args:
        request_token: Token from the X-Gitlab-Token header.
        expected_token: Expected secret token (default: AIIR_WEBHOOK_SECRET env var).

    Returns:
        True if valid, False otherwise.
    """
    import hmac

    expected = expected_token or os.environ.get("AIIR_WEBHOOK_SECRET", "")
    if not expected:
        logger.warning(
            "AIIR_WEBHOOK_SECRET not set — rejecting webhook "
            "(set AIIR_WEBHOOK_ALLOW_UNSIGNED=1 to allow unsigned webhooks)"
        )
        # Fail-closed: reject all webhooks when no secret is configured,
        # unless the operator explicitly opts in to unsigned webhooks.
        return os.environ.get("AIIR_WEBHOOK_ALLOW_UNSIGNED") == "1"
    return hmac.compare_digest(request_token, expected)


# ---------------------------------------------------------------------------
# GraphQL: receipt data queries
# ---------------------------------------------------------------------------


def build_receipts_graphql_query(
    project_path: str,
    package_name: str = "aiir-receipts",
) -> Dict[str, Any]:
    """Build a GitLab GraphQL query with parameterized variables.

    AIIR receipts can be stored as GitLab Generic Package artifacts.
    This builds a query to list available receipt packages, enabling
    GitLab Duo Chat or other integrations to answer "what % of this
    MR was AI-written?"

    Returns a dict with ``query`` and ``variables`` keys suitable for
    passing directly to :func:`query_gitlab_graphql`.  Using GraphQL
    variables instead of string interpolation prevents injection attacks
    (even with backslash-escape bypasses).

    https://docs.gitlab.com/ee/api/graphql/reference/index.html

    Args:
        project_path: Full project path (e.g., ``group/project``).
        package_name: Package name to search for.

    Returns:
        Dict with ``query`` (parameterized) and ``variables``.
    """
    query = """\
query($fullPath: ID!, $pkgName: String!) {
  project(fullPath: $fullPath) {
    packages(
      packageName: $pkgName
      packageType: GENERIC
      first: 20
      sort: CREATED_DESC
    ) {
      nodes {
        id
        name
        version
        createdAt
        metadata {
          ... on ComposerMetadata {
            composerJson
          }
        }
        packageFiles(first: 50) {
          nodes {
            fileName
            fileSha256
            size
            downloadPath
            createdAt
          }
        }
      }
    }
  }
}"""
    variables = {
        "fullPath": _strip_terminal_escapes(project_path),
        "pkgName": _strip_terminal_escapes(package_name),
    }
    return {"query": query, "variables": variables}


def query_gitlab_graphql(
    query: str,
    variables: Optional[Dict[str, Any]] = None,
    api_url: Optional[str] = None,
    token: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute a GraphQL query against the GitLab API.

    Args:
        query: GraphQL query string (should use ``$variable`` placeholders).
        variables: GraphQL variable dict (prevents injection attacks).
        api_url: GitLab instance URL (auto-detected from CI_SERVER_URL).
        token: Auth token (uses GITLAB_TOKEN or CI_JOB_TOKEN).

    Returns:
        Parsed GraphQL response data.

    Raises:
        RuntimeError: If the query fails.
    """
    base = api_url or os.environ.get("CI_SERVER_URL", "https://gitlab.com")
    url = f"{base.rstrip('/')}/api/graphql"

    auth_token = (
        token or os.environ.get("GITLAB_TOKEN") or os.environ.get("CI_JOB_TOKEN")
    )
    if not auth_token:
        raise RuntimeError("No GitLab auth token for GraphQL query")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {auth_token}",
    }

    payload: Dict[str, Any] = {"query": query}
    if variables:
        payload["variables"] = variables
    data = json.dumps(payload).encode("utf-8")
    req = Request(url, data=data, headers=headers, method="POST")

    try:
        with urlopen(req, timeout=_API_TIMEOUT) as resp:  # nosec B310  # nosemgrep
            result = json.loads(resp.read().decode("utf-8"))
            if "errors" in result:
                raise RuntimeError(
                    f"GraphQL errors: {json.dumps(result['errors'][:3])}"
                )
            gql_data: dict[str, Any] = result.get("data", {})
            return gql_data
    except HTTPError as e:
        error_body = ""
        try:
            error_body = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        raise RuntimeError(f"GitLab GraphQL error {e.code}: {error_body}") from e
    except URLError as e:
        raise RuntimeError(f"GitLab GraphQL connection error: {e.reason}") from e


# ---------------------------------------------------------------------------
# GitLab Pages dashboard: static HTML generation
# ---------------------------------------------------------------------------


def generate_dashboard_html(
    receipts: List[Dict[str, Any]],
    project_name: str = "",
) -> str:
    """Generate a static HTML dashboard for GitLab Pages.

    Creates a single-page dashboard showing:
    - AI authorship percentage over time
    - Authorship class breakdown
    - Recent receipt history

    Deploy via GitLab Pages:
        pages:
          stage: deploy
          script:
            - aiir --stats --gitlab-ci
            - python -c "from aiir._gitlab import generate_dashboard_html; ..."
          artifacts:
            paths:
              - public/

    Args:
        receipts: List of AIIR receipt dicts.
        project_name: Project name for the title.

    Returns:
        Complete HTML string for the dashboard page.
    """
    total = len(receipts)
    ai_count = sum(
        1
        for r in receipts
        if isinstance(r.get("ai_attestation"), dict)
        and r["ai_attestation"].get("is_ai_authored")
    )
    bot_count = sum(
        1
        for r in receipts
        if isinstance(r.get("ai_attestation"), dict)
        and r["ai_attestation"].get("is_bot_authored")
    )
    human_count = total - ai_count - bot_count

    # Authorship class breakdown
    classes: Dict[str, int] = {}
    for r in receipts:
        ai = r.get("ai_attestation", {})
        if isinstance(ai, dict):
            cls = ai.get("authorship_class", "unknown")
            classes[cls] = classes.get(cls, 0) + 1

    ai_pct = (ai_count / total * 100) if total > 0 else 0
    safe_project = html.escape(_strip_terminal_escapes(project_name or "Project"))

    # Build class breakdown rows
    class_rows = ""
    for cls, count in sorted(classes.items(), key=lambda x: -x[1]):
        pct = count / total * 100 if total > 0 else 0
        icon = {"human": "👤", "ai_assisted": "🤖", "bot": "⚙️", "ai+bot": "🤖⚙️"}.get(
            cls, "❓"
        )
        safe_cls = html.escape(_strip_terminal_escapes(cls))
        class_rows += (
            f"<tr><td>{icon} {safe_cls}</td><td>{count}</td><td>{pct:.1f}%</td></tr>\n"
        )

    # Build recent receipts rows (last 50)
    receipt_rows = ""
    for r in receipts[:50]:
        commit = r.get("commit", {})
        ai = r.get("ai_attestation", {})
        if not isinstance(commit, dict):
            commit = {}
        if not isinstance(ai, dict):
            ai = {}
        sha = html.escape(_strip_terminal_escapes(str(commit.get("sha", "")))[:8])
        subj = html.escape(_strip_terminal_escapes(str(commit.get("subject", "")))[:60])
        cls = html.escape(
            _strip_terminal_escapes(str(ai.get("authorship_class", "unknown")))
        )
        ts = html.escape(_strip_terminal_escapes(str(r.get("timestamp", "")))[:19])
        receipt_rows += f"<tr><td><code>{sha}</code></td><td>{subj}</td><td>{cls}</td><td>{ts}</td></tr>\n"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AIIR Dashboard — {safe_project}</title>
<style>
:root {{ --bg: #0d1117; --surface: #161b22; --border: #30363d; --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff; --green: #3fb950; --orange: #d29922; --red: #f85149; }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }}
h1 {{ font-size: 1.5rem; margin-bottom: 0.5rem; }}
.subtitle {{ color: var(--muted); margin-bottom: 2rem; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
.card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; }}
.card .label {{ color: var(--muted); font-size: 0.875rem; }}
.card .value {{ font-size: 2rem; font-weight: 600; margin-top: 0.25rem; }}
.card .value.green {{ color: var(--green); }}
.card .value.orange {{ color: var(--orange); }}
.card .value.accent {{ color: var(--accent); }}
table {{ width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; margin-bottom: 2rem; }}
th {{ background: var(--bg); text-align: left; padding: 0.75rem 1rem; font-size: 0.875rem; color: var(--muted); border-bottom: 1px solid var(--border); }}
td {{ padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.875rem; }}
tr:last-child td {{ border-bottom: none; }}
.footer {{ color: var(--muted); font-size: 0.75rem; margin-top: 2rem; }}
code {{ background: var(--bg); padding: 0.2em 0.4em; border-radius: 3px; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>🔐 AIIR Dashboard</h1>
<p class="subtitle">{safe_project} — AI Integrity Receipts</p>

<div class="grid">
  <div class="card"><div class="label">Total Receipts</div><div class="value accent">{total}</div></div>
  <div class="card"><div class="label">AI-Authored</div><div class="value orange">{ai_count} ({ai_pct:.1f}%)</div></div>
  <div class="card"><div class="label">Human</div><div class="value green">{human_count}</div></div>
  <div class="card"><div class="label">Bot</div><div class="value">{bot_count}</div></div>
</div>

<h2 style="margin-bottom: 1rem;">Authorship Breakdown</h2>
<table>
<thead><tr><th>Class</th><th>Count</th><th>Percentage</th></tr></thead>
<tbody>{class_rows}</tbody>
</table>

<h2 style="margin-bottom: 1rem;">Recent Receipts</h2>
<table>
<thead><tr><th>Commit</th><th>Subject</th><th>Class</th><th>Time</th></tr></thead>
<tbody>{receipt_rows}</tbody>
</table>

<div class="footer">
Generated by <a href="https://github.com/invariant-systems-ai/aiir" style="color: var(--accent);">AIIR</a> v{CLI_VERSION}
· {_safe_iso_now()} UTC
</div>
</body>
</html>"""
