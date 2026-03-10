# GitLab Webhooks — Server-Side Receipt Generation

> Generate AIIR receipts automatically via GitLab webhooks — no CI
> pipeline needed. Useful for real-time receipt generation, centralized
> audit servers, and air-gapped environments.

## Overview

GitLab [project webhooks](https://docs.gitlab.com/ee/user/project/integrations/webhooks.html)
send HTTP POST requests when events occur (push, MR open, etc.). AIIR
can receive these events and generate receipts server-side.

## Quick Setup

### 1. Create the webhook receiver

```python
#!/usr/bin/env python3
"""AIIR webhook receiver — generates receipts from GitLab push/MR events."""

import json
import os
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler

from aiir._gitlab import parse_webhook_event, validate_webhook_token
from aiir._receipt import generate_receipts_for_range
from aiir._gitlab import format_gitlab_summary, post_mr_comment


class AIIRWebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Validate webhook token
        token = self.headers.get("X-Gitlab-Token", "")
        if not validate_webhook_token(token):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'{"error": "invalid token"}')
            return

        # Parse payload
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length))

        event = parse_webhook_event(payload)
        if not event:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status": "ignored"}')
            return

        # Clone/fetch the repo and generate receipts
        if event["event_type"] == "push" and event.get("before") and event.get("after"):
            range_spec = f"{event['before']}..{event['after']}"
            # You'd clone/fetch the repo here, then:
            # receipts = generate_receipts_for_range(range_spec, cwd=repo_path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "processed",
                "event": event["event_type"],
                "range": range_spec,
            }).encode())

        elif event["event_type"] == "merge_request":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "processed",
                "event": event["event_type"],
                "mr_iid": event.get("mr_iid"),
            }).encode())

        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status": "ignored"}')


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), AIIRWebhookHandler)
    print("AIIR webhook receiver running on :8080")
    server.serve_forever()
```

### 2. Configure the webhook in GitLab

<!-- markdownlint-disable-next-line MD036 -->
**Project → Settings → Webhooks → Add webhook**

- **URL**: `https://your-server.example.com/aiir/webhook`
- **Secret token**: Set `AIIR_WEBHOOK_SECRET` on your server to match
- **Trigger**: ✅ Push events, ✅ Merge request events
- **SSL verification**: ✅ Enable

### 3. Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AIIR_WEBHOOK_SECRET` | Recommended | Secret token for webhook validation |
| `GITLAB_TOKEN` | For MR comments | Token with `api` scope for posting MR comments |

## Webhook payload parsing

AIIR's `parse_webhook_event()` normalizes both push and MR events:

```python
from aiir._gitlab import parse_webhook_event

# Push event
event = parse_webhook_event(push_payload)
# Returns: {
#   "event_type": "push",
#   "project_id": "123",
#   "project_path": "group/project",
#   "ref": "refs/heads/main",
#   "before": "abc123...",
#   "after": "def456...",
#   "commit_count": "3"
# }

# MR event
event = parse_webhook_event(mr_payload)
# Returns: {
#   "event_type": "merge_request",
#   "project_id": "123",
#   "project_path": "group/project",
#   "mr_iid": "42",
#   "mr_action": "open",
#   "source_branch": "feature",
#   "target_branch": "main",
#   "before": "...",
#   "after": "..."
# }
```

## Security considerations

- Always set `AIIR_WEBHOOK_SECRET` and enable SSL verification
- `validate_webhook_token()` uses constant-time comparison (no timing leaks)
- All payload fields are sanitized against terminal escape injection
- The webhook handler should run behind a reverse proxy (nginx, Caddy)

---

**Links**: [AIIR on PyPI](https://pypi.org/project/aiir/) ·
[GitLab Webhooks](https://docs.gitlab.com/ee/user/project/integrations/webhooks.html) ·
[Webhook Events](https://docs.gitlab.com/ee/user/project/integrations/webhook_events.html)
